"""Combined browser/MCP HTTP contract, with real per-account age ciphertext."""
from __future__ import annotations

import asyncio
import json
import subprocess
from urllib.parse import quote

import pytest
from mcp.server import MCPServer
from starlette.testclient import TestClient

from passage_mcp import server
from passage_mcp.config import Config
from passage_mcp.store import AgeStore
from passage_mcp.web import ORIGIN


def identity(sub):
    return {
        'X-Lost-Plus-Encoding': 'percent-utf8',
        'X-Lost-Plus-Sub': quote(sub, safe=''),
        'X-Lost-Plus-Email': quote(sub + '@example.test'),
        'X-Lost-Plus-Name': 'Integration',
        'X-Lost-Plus-Role': 'user',
    }


@pytest.fixture
def combined(tmp_path, monkeypatch):
    for name in ('SECRETS_STORE_DIR', 'AGE_IDENTITY_FILE', 'LEGACY_OWNER_SUB',
                 'TENANTS_DIR', 'TENANT_KEYS_DIR'):
        monkeypatch.delenv(name, raising=False)
    key = tmp_path / 'owner.key'
    subprocess.run(['age-keygen', '-o', str(key)], check=True, capture_output=True)
    public = subprocess.run(['age-keygen', '-y', str(key)], check=True, capture_output=True).stdout
    root = tmp_path / 'owner'
    root.mkdir()
    (root / '.age-recipients').write_bytes(public)
    owner = AgeStore(Config(root, key))

    async def seed():
        await owner.add_folder('original')
        await owner.add_secret('original', 'saved', 'owner-value')
        await owner.close()
    asyncio.run(seed())
    config = tmp_path / 'http.json'
    config.write_text(json.dumps({
        'store_dir': str(root), 'identity_file': str(key), 'legacy_owner_sub': '1',
        'tenants_dir': str(tmp_path / 'tenants'), 'tenant_keys_dir': str(tmp_path / 'keys'),
    }))
    mcp = MCPServer('combined-http-test')
    server._register_tools(mcp)
    server._register_routes(mcp)
    with TestClient(server._build_app(mcp, str(config))) as client:
        yield client, tmp_path


def browser(client, sub, operation, **arguments):
    response = client.post('/api/' + operation, json=arguments, headers={
        **identity(sub), 'X-Passage-Subject': sub, 'Origin': ORIGIN,
    })
    assert response.status_code == 200, response.text
    return response.json()['data']


def mcp_tool(client, sub, name, **arguments):
    response = client.post('/mcp', headers={
        **identity(sub), 'Accept': 'application/json, text/event-stream',
    }, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
             'params': {'name': name, 'arguments': arguments}})
    assert response.status_code == 200, response.text
    result = response.json()['result']
    assert not result.get('isError'), result
    return result['content'][0]['text']


def test_session_assets_and_rejections_do_not_allocate(combined):
    client, path = combined
    for sub in ('alice', 'bob', '1'):
        response = client.get('/api/session', headers=identity(sub))
        assert response.status_code == 200
        assert response.json()['sub'] == sub
        assert response.headers['cache-control'] == 'no-store'
    assert list((path / 'tenants').iterdir()) == []
    assert list((path / 'keys').iterdir()) == []
    for headers in ({}, identity('alice') | {'X-Lost-Plus-Sub': '%zz'}):
        for endpoint in ('/api/session', '/', '/mcp'):
            assert client.get(endpoint, headers=headers).status_code == 401
        assert client.post('/api/folders/create', json={'folder': 'forbidden'},
                           headers=headers).status_code == 401
    valid = identity('alice') | {'X-Passage-Subject': 'alice', 'Origin': ORIGIN}
    for missing in ('X-Passage-Subject', 'Origin'):
        headers = {key: value for key, value in valid.items() if key != missing}
        assert client.post('/api/folders/create', json={'folder': 'forbidden'},
                           headers=headers).status_code == 403
    for change in ({'X-Passage-Subject': 'bob'}, {'X-Passage-Subject': ''},
                   {'Origin': 'https://evil.example'}, {'Origin': ''}):
        assert client.post('/api/folders/create', json={'folder': 'forbidden'},
                           headers=valid | change).status_code == 403
    assert list((path / 'tenants').iterdir()) == []
    assert list((path / 'keys').iterdir()) == []
    for asset, content_type in (('/', 'text/html'), ('/assets/vault.js', 'text/javascript'),
                                ('/assets/vault.css', 'text/css'), ('/assets/tokens.css', 'text/css')):
        response = client.get(asset, headers=identity('1'))
        assert response.status_code == 200
        assert response.headers['content-type'].startswith(content_type)
        assert response.content
    assert client.get('/assets/missing', headers=identity('1')).status_code == 404
    assert list((path / 'tenants').iterdir()) == []


def test_browser_and_mcp_share_only_the_authenticated_vault(combined):
    client, path = combined
    owner_before = {p.relative_to(path / 'owner'): p.read_bytes()
                    for p in (path / 'owner').rglob('*') if p.is_file()}
    key_before = (path / 'owner.key').read_bytes()
    for sub in ('alice', 'bob'):
        assert browser(client, sub, 'folders/list') == []
        browser(client, sub, 'folders/create', folder='same')
        browser(client, sub, 'folders/create', folder='destination')
        browser(client, sub, 'secrets/create', folder='same', item_name='secret', value=sub)
        browser(client, sub, 'logins/create', folder='same', item_name='login',
                username=sub, password=sub + '-password')
    for sub in ('alice', 'bob', 'alice'):
        assert browser(client, sub, 'secrets/read', folder='same', item_name='login') == {
            'username': sub, 'password': sub + '-password'}
        assert mcp_tool(client, sub, 'get_secret', folder='same', item_name='secret') == sub
        assert json.loads(mcp_tool(client, sub, 'get_login', folder='same', item_name='login')) == {
            'username': sub, 'password': sub + '-password'}
        assert len(browser(client, sub, 'secrets/search', query='secret')) == 1
    # Alter one account while the other retains its original names and values.
    browser(client, 'alice', 'secrets/update', folder='same', item_name='secret', value='edited')
    browser(client, 'alice', 'secrets/rename', folder='same', item_name='secret', new_name='renamed')
    browser(client, 'alice', 'secrets/move', folder='same', item_name='renamed', target_folder='destination')
    browser(client, 'alice', 'folders/rename', folder='destination', new_name='moved')
    assert mcp_tool(client, 'alice', 'get_secret', folder='moved', item_name='renamed') == 'edited'
    assert mcp_tool(client, 'bob', 'get_secret', folder='same', item_name='secret') == 'bob'
    browser(client, 'alice', 'secrets/delete', folder='moved', item_name='renamed')
    assert len(browser(client, 'alice', 'trash/list')) == 1
    assert browser(client, 'bob', 'trash/list') == []
    browser(client, 'alice', 'trash/recover', folder='moved', item_name='renamed')
    assert browser(client, 'alice', 'secrets/read', folder='moved', item_name='renamed')['password'] == 'edited'
    browser(client, 'alice', 'secrets/delete', folder='moved', item_name='renamed')
    browser(client, 'alice', 'trash/empty')
    assert browser(client, 'alice', 'trash/list') == []
    browser(client, 'alice', 'folders/delete', folder='moved')
    assert browser(client, 'bob', 'folders/list') == [{'name': 'destination'}, {'name': 'same'}]
    for sub in ('alice', 'bob'):
        response = client.post('/api/secrets/read', json={'folder': 'original', 'item_name': 'saved'},
                               headers=identity(sub) | {'X-Passage-Subject': sub, 'Origin': ORIGIN})
        assert response.status_code == 404
    assert mcp_tool(client, '1', 'get_secret', folder='original', item_name='saved') == 'owner-value'
    assert browser(client, '1', 'secrets/read', folder='original', item_name='saved')['password'] == 'owner-value'
    assert owner_before == {p.relative_to(path / 'owner'): p.read_bytes()
                            for p in (path / 'owner').rglob('*') if p.is_file()}
    assert (path / 'owner.key').read_bytes() == key_before
    assert len(list((path / 'tenants').iterdir())) == 2
    keys = list((path / 'keys').glob('*.key'))
    assert len(keys) == 2 and keys[0].read_bytes() != keys[1].read_bytes()
