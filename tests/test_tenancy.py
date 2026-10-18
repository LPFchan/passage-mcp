from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from urllib.parse import quote

import pytest

from passage_mcp.config import Config
from passage_mcp.identity import header_values, identity_from
from passage_mcp.store import AgeStore, ForbiddenError, InternalError, NotFoundError
from passage_mcp.tenancy import TenantManager
from passage_mcp import server


def headers(sub='alice', **changes):
    result = {'x-lost-plus-encoding': 'percent-utf8', 'x-lost-plus-sub': quote(sub),
              'x-lost-plus-email': 'me%2Btag%40lost.plus', 'x-lost-plus-name': '%EC%82%AC%EC%9A%A9%EC%9E%90',
              'x-lost-plus-role': 'user'}
    result.update(changes)
    return result


@pytest.mark.parametrize('bad', ['%', '%E', '%zz', '%FF', '%C0%AF', '%ED%A0%80', ''])
def test_identity_refuses_bad_fields(bad):
    for field in ('sub', 'email', 'name', 'role'):
        assert identity_from(headers(**{'x-lost-plus-' + field: bad})) is None


def test_identity_contract():
    assert identity_from(headers()) == dict(sub='alice', email='me+tag@lost.plus', name='사용자', role='user')
    assert identity_from(headers(**{'x-lost-plus-name': 'a+b%20c%0D%0A', 'x-lost-plus-role': ' odd'}))['name'] == 'a+b c\r\n'
    assert identity_from(headers(**{'x-lost-plus-sub': '4%002'}))['sub'] == '4\x002'
    for key in headers():
        h = headers(); del h[key]
        assert identity_from(h) is None
    assert identity_from(headers(**{'x-lost-plus-encoding': 'Percent-UTF8'})) is None
    assert identity_from(header_values([(b'x-lost-plus-encoding', b'percent-utf8')] * 2)) is None


@pytest.fixture
def setup(tmp_path):
    key = tmp_path / 'owner.key'
    subprocess.run(['age-keygen', '-o', str(key)], capture_output=True, check=True)
    pub = subprocess.run(['age-keygen', '-y', str(key)], capture_output=True, check=True).stdout
    root = tmp_path / 'owner'; root.mkdir()
    (root / '.age-recipients').write_bytes(pub)
    config = Config(root, key, legacy_owner_sub='owner', tenants_dir=tmp_path / 'tenants', tenant_keys_dir=tmp_path / 'keys')
    owner = AgeStore(config)
    return config, owner


def test_two_user_all_operations_and_owner_preservation(setup):
    config, owner = setup
    async def scenario():
        await owner.add_folder('original')
        await owner.add_secret('original', 'saved', 'owner-secret')
        before = (config.store_dir / 'original/saved.age').read_bytes()
        key_before = config.identity_file.read_bytes()
        manager = TenantManager(config, owner)
        assert await manager.get_store('owner') is owner
        a, b = await asyncio.gather(manager.get_store('alice'), manager.get_store('bob'))
        assert a._identity.read_bytes() != b._identity.read_bytes()
        for store, value in ((a, 'alice-value'), (b, 'bob-value')):
            await store.add_folder('same'); await store.add_folder('target')
            await store.add_secret('same', 'secret', value)
            await store.add_login('same', 'login', value, value)
        for store, value in ((a, 'alice-value'), (b, 'bob-value')):
            assert await store.get_secret('same', 'secret') == value
            assert (await store.get_login('same', 'login'))['username'] == value
            assert len(await store.list_secrets('same')) == 1
            assert len(await store.search_secrets('secret')) == 1
            await store.edit_secret('same', 'secret', value + '-edited')
            await store.move_secret('same', 'secret', 'target')
            await store.rename_secret('target', 'secret', 'renamed')
            await store.delete_secret('target', 'renamed')
            assert len(await store.list_trash()) == 1
            await store.rename_folder('target', 'renamed-folder')
            await store.recover_secret('renamed-folder', 'renamed')
            assert await store.get_secret('renamed-folder', 'renamed') == value + '-edited'
            await store.delete_secret('renamed-folder', 'renamed')
            await store.empty_trash()
            assert await store.list_trash() == []
            await store.delete_folder('renamed-folder')
            assert await store.list_folders() == [{'name': 'same'}]
        with pytest.raises(InternalError):
            await a._run('age', '-d', '-i', str(a._identity), str(b._root / 'same/login.age'))
        assert before == (config.store_dir / 'original/saved.age').read_bytes()
        assert key_before == config.identity_file.read_bytes()
        assert await owner.get_secret('original', 'saved') == 'owner-secret'
        assert len(manager._locks) == 64
    asyncio.run(scenario())


def test_provision_race(setup):
    config, owner = setup
    async def scenario():
        managers = [TenantManager(config, owner) for _ in range(4)]
        stores = await asyncio.gather(*(managers[i % 4].get_store('../alice/😀') for i in range(16)))
        assert len({s._identity.read_bytes() for s in stores}) == 1
        assert len(list(config.tenants_dir.iterdir())) == 1
        assert stores[0]._root.stat().st_mode & 0o777 == 0o700
        assert stores[0]._identity.stat().st_mode & 0o777 == 0o600
        await stores[0].validate()
    asyncio.run(scenario())


def test_required_owner_and_separate_paths(setup):
    config, owner = setup
    config.legacy_owner_sub = None
    with pytest.raises(InternalError): TenantManager(config, owner)
    config.legacy_owner_sub = 'owner'; config.tenants_dir = config.store_dir / 'tenants'
    with pytest.raises(InternalError): TenantManager(config, owner)


def test_symlink_confinement(setup, tmp_path):
    config, owner = setup
    outside = tmp_path / 'outside'; outside.mkdir()
    (outside / 'secret.age').write_text('untouched')
    (config.store_dir / 'escape').symlink_to(outside)
    async def scenario():
        operations = [owner.get_secret('escape', 'secret'), owner.add_secret('escape', 'new', 'v'),
                      owner.list_secrets(), owner.list_secrets('escape'), owner.search_secrets('secret'),
                      owner.rename_folder('escape', 'new'), owner.delete_folder('escape')]
        for op in operations:
            with pytest.raises(ForbiddenError): await op
        (config.store_dir / 'escape').unlink()
        (config.store_dir / '.trash').symlink_to(outside)
        for op in (owner.list_trash(), owner.empty_trash(), owner.recover_secret('escape', 'secret')):
            with pytest.raises(ForbiddenError): await op
        assert (outside / 'secret.age').read_text() == 'untouched'
    asyncio.run(scenario())


async def call(app, sub='alice', path='/api/items', method='GET', extra=None):
    h = headers(sub); h.update(extra or {})
    messages = []
    async def send(message): messages.append(message)
    async def receive(): return {'type': 'http.request', 'body': b''}
    scope = dict(type='http', path=path, method=method, headers=[(k.encode(), v.encode()) for k, v in h.items()])
    await app(scope, receive, send)
    return messages


def test_http_boundary_and_concurrent_context(setup, monkeypatch):
    config, owner = setup
    manager = TenantManager(config, owner)
    monkeypatch.setattr(server, '_tenants', manager)
    monkeypatch.setattr(server, '_http_mode', True)
    seen = []
    async def endpoint(scope, receive, send):
        if scope['path'] == '/api/session':
            with pytest.raises(InternalError): server._require_client()
        elif scope['path'] != '/healthz':
            store = server._require_client()
            await asyncio.sleep(0.01)
            assert server._require_client() is store
            seen.append((scope['state']['passage_identity']['sub'], store._root.name))
        await server.JSONResponse({'ok': True})(scope, receive, send)
    app = server._IdentityMiddleware(endpoint)
    async def scenario():
        assert (await call(app, path='/api/session'))[0]['status'] == 200
        assert list(config.tenants_dir.iterdir()) == []
        for h in ({}, {'x-passage-subject': 'bob'}, {'x-passage-subject': 'alice', 'origin': 'https://evil.example'}):
            assert (await call(app, method='POST', extra=h))[0]['status'] == 403
        for h in ({'x-lost-plus-sub': '%zz'}, {'x-lost-plus-encoding': ''}):
            assert (await call(app, path='/mcp', extra=h))[0]['status'] == 401
        assert (await call(app, path='/healthz', extra={'x-lost-plus-sub': ''}))[0]['status'] == 200
        await asyncio.gather(*(call(app, sub=s, extra={'x-passage-subject': s}) for s in ['alice', 'bob'] * 6))
        assert all(name == hashlib.sha256(sub.encode()).hexdigest() for sub, name in seen)
        assert server._request_client.get() is None
        assert (await call(app, method='POST', extra={'x-passage-subject': 'alice', 'origin': 'https://passage.lost.plus'}))[0]['status'] == 200
        with pytest.raises(InternalError): server._require_client()
    asyncio.run(scenario())


def test_context_cleanup_after_error(setup, monkeypatch):
    config, owner = setup
    monkeypatch.setattr(server, '_tenants', TenantManager(config, owner))
    async def fail(*args): raise RuntimeError('failed')
    async def scenario():
        with pytest.raises(RuntimeError): await call(server._IdentityMiddleware(fail), path='/mcp')
        assert server._request_client.get() is None
    asyncio.run(scenario())


def test_stdio_lifespan_keeps_single_store(setup, tmp_path):
    config, owner = setup
    path = tmp_path / 'config.json'
    path.write_text(json.dumps({'store_dir': str(config.store_dir), 'identity_file': str(config.identity_file)}))
    async def scenario():
        async with server._build_lifespan(str(path))(None):
            assert server._tenants is None
            assert server._require_client()._root == config.store_dir
        assert server._client is None
    asyncio.run(scenario())


def test_config_env(monkeypatch):
    monkeypatch.setenv('LEGACY_OWNER_SUB', 'subject')
    monkeypatch.setenv('TENANTS_DIR', '/tmp/ciphertext')
    monkeypatch.setenv('TENANT_KEYS_DIR', '/tmp/keys')
    config = Config.from_dict({})
    assert config.legacy_owner_sub == 'subject'
    assert str(config.tenants_dir) == '/tmp/ciphertext'
    assert str(config.tenant_keys_dir) == '/tmp/keys'


def test_real_http_mcp_tools_keep_request_tenant(setup, tmp_path):
    from mcp.server import MCPServer
    from starlette.testclient import TestClient
    config, owner = setup
    path = tmp_path / 'http.json'
    path.write_text(json.dumps({'store_dir': str(config.store_dir), 'identity_file': str(config.identity_file),
                               'legacy_owner_sub': 'owner', 'tenants_dir': str(config.tenants_dir),
                               'tenant_keys_dir': str(config.tenant_keys_dir)}))
    mcp = MCPServer('test')
    server._register_tools(mcp)
    app = server._build_app(mcp, str(path))
    with TestClient(app) as client:
        assert server._tenants is not None
        def tool(sub, name, arguments):
            h = headers(sub)
            h['accept'] = 'application/json, text/event-stream'
            response = client.post('/mcp', headers=h, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                                                          'params': {'name': name, 'arguments': arguments}})
            assert response.status_code == 200, response.text
            return response.json()['result']
        for sub in ('alice', 'bob'):
            assert not tool(sub, 'add_folder', {'folder': 'private'}).get('isError')
            assert not tool(sub, 'add_secret', {'folder': 'private', 'item_name': 'same', 'value': sub}).get('isError')
        for sub in ('alice', 'bob', 'alice'):
            result = tool(sub, 'get_secret', {'folder': 'private', 'item_name': 'same'})
            assert not result.get('isError'), result
            assert result['content'][0]['text'] == sub
    assert server._tenants is None
    assert server._client is None


def test_real_stdio_retains_owner_store(setup, tmp_path):
    import sys
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    config, owner = setup
    path = tmp_path / 'stdio.json'
    path.write_text(json.dumps({'store_dir': str(config.store_dir), 'identity_file': str(config.identity_file)}))
    async def scenario():
        params = StdioServerParameters(command=sys.executable, args=['-m', 'passage_mcp.server', '--stdio', '--config', str(path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                assert not (await session.call_tool('add_folder', {'folder': 'stdio'})).is_error
                assert not (await session.call_tool('add_secret', {'folder': 'stdio', 'item_name': 'saved', 'value': 'owner-value'})).is_error
                result = await session.call_tool('get_secret', {'folder': 'stdio', 'item_name': 'saved'})
                assert result.content[0].text == 'owner-value'
        assert await owner.get_secret('stdio', 'saved') == 'owner-value'
        assert not config.tenants_dir.exists()
    asyncio.run(scenario())
