"""Browser routes tested without trusting the deployment middleware."""
from contextvars import ContextVar
from urllib.parse import quote, unquote

import pytest
from unittest.mock import AsyncMock
from mcp.server import MCPServer
from starlette.testclient import TestClient

from passage_mcp.web import HEADERS, MAX_BODY, ORIGIN, register_routes
from passage_mcp.store import InternalError
from test_store import store  # reuse real age-encrypted fixture


@pytest.fixture
def client(store):
    current = ContextVar('web_test_store')
    calls = []
    bob_store = AsyncMock()
    bob_store.list_folders.return_value = [{'name':'bob-private-folder'}]
    def get_store():
        calls.append(True)
        return current.get()
    server = MCPServer('web-test')
    register_routes(server, get_store)
    inner = server.streamable_http_app(stateless_http=True)
    async def identity_app(scope, receive, send):
        scope['state'] = dict(scope.get('state', {}))
        scope['state'].pop('passage_identity', None)
        headers = dict(scope.get('headers', []))
        sub = unquote(headers.get(b'x-test-account', b'alice').decode(), errors='strict')
        if sub != 'anonymous':
            scope['state']['passage_identity'] = {'sub':sub, 'email':sub+'@example.com', 'private':'omit'}
        token = current.set(bob_store if sub == 'bob' else store)
        try:
            await inner(scope, receive, send)
        finally:
            current.reset(token)
    with TestClient(identity_app) as c:
        c.headers.update({'Origin':ORIGIN, 'X-Passage-Subject':'alice'})
        c.store_calls = calls
        c.store = store
        yield c


def post(client, path, **data):
    return client.post('/api/'+path, json=data)


def test_session_and_guards(client):
    session = client.get('/api/session')
    assert session.json()['sub'] == 'alice'
    assert 'private' not in session.json()
    assert post(client,'folders/list').status_code == 200
    n = len(client.store_calls)
    assert client.post('/api/folders/list',json={},headers={'X-Test-Account':'bob'}).status_code == 409
    assert client.post('/api/folders/list',json={},headers={'Origin':'https://evil.example'}).status_code == 403
    assert client.post('/api/folders/list',json={},headers={'Origin':''}).status_code == 403
    assert client.post('/api/folders/list',json={},headers={'X-Test-Account':'anonymous'}).status_code == 401
    assert client.get('/api/session',headers={'X-Test-Account':'anonymous'}).status_code == 401
    assert len(client.store_calls) == n


@pytest.mark.parametrize('sub', ['여우😀 +%2F/', 'café', '42', '%FF'])
def test_route_decodes_subject_without_middleware(client, sub):
    encoded = quote(sub, safe="~()*!.'-")
    response = client.post('/api/folders/list', json={}, headers={
        'X-Test-Account': encoded, 'X-Passage-Subject': encoded,
    })
    assert response.status_code == 200
    assert len(client.store_calls) == 1


@pytest.mark.parametrize('bad', ['', '%', '%E', '%zz', '%FF', '%C0%AF', '%ED%A0%80', '%F0%9F'])
def test_route_rejects_malformed_subject_without_store(client, bad):
    response = client.post('/api/folders/list', json={}, headers={
        'X-Test-Account': quote(bad or 'alice', safe=''), 'X-Passage-Subject': bad,
    })
    assert response.status_code == 409
    assert not client.store_calls


@pytest.mark.parametrize('data', [[], {'folder':1}, {'folder':'x','extra':'x'}, {'method':'empty_trash'}, None])
def test_malformed_fields(client,data):
    assert client.post('/api/folders/create',json=data).status_code == 400
    assert not client.store_calls


def test_malformed_and_oversized(client):
    assert client.post('/api/folders/create',content='{',headers={'Content-Type':'application/json'}).status_code == 400
    assert client.post('/api/folders/create',content='{}').status_code == 400
    assert client.post('/api/folders/create',content=b'x'*(MAX_BODY+1),headers={'Content-Type':'application/json'}).status_code == 413
    assert not client.store_calls


def test_crud_and_trash(client):
    assert post(client,'folders/create',folder='web').status_code == 200
    assert post(client,'folders/create',folder='web').status_code == 409
    assert post(client,'folders/rename',folder='web',new_name='renamed').status_code == 200
    base={'folder':'renamed','item_name':'<script>alert(1)</script>'}
    # Names with path separators are refused; HTML-like text without separators is valid.
    assert post(client,'secrets/create',**base,value='private').status_code == 400
    base['item_name']='<img onerror=alert(1)>'
    assert post(client,'logins/create',**base,username='alice',password='private').status_code == 200
    assert post(client,'secrets/update',**base,value='new').status_code == 200
    assert post(client,'secrets/read',**base).json()['data'] == {'username':'alice','password':'new'}
    assert post(client,'secrets/search',query='onerror').json()['data'][0]['item_name'] == base['item_name']
    listing=post(client,'secrets/list',folder='renamed')
    assert 'private' not in listing.text and 'password' not in listing.text
    assert post(client,'secrets/rename',**base,new_name='entry').status_code == 200
    base['item_name']='entry'
    assert post(client,'secrets/move',**base,target_folder='infra').status_code == 200
    base['folder']='infra'
    assert post(client,'secrets/delete',**base).status_code == 200
    assert post(client,'trash/list').json()['data'][0]['name'] == 'entry'
    assert post(client,'trash/recover',**base).status_code == 200
    assert post(client,'secrets/delete',**base).status_code == 200
    assert post(client,'trash/empty').status_code == 200
    assert post(client,'trash/list').json()['data'] == []
    assert post(client,'folders/delete',folder='renamed').status_code == 200
    assert post(client,'secrets/read',**base).status_code == 404


def test_dashboard_redirect_and_private_headers(client):
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 308
    assert response.headers['location'] == 'https://auth.lost.plus/#passage'
    for response in [response, client.get('/api/session'),
                     post(client, 'secrets/read', folder='missing', item_name='x')]:
        for key, value in HEADERS.items():
            assert response.headers[key] == value
    assert client.get('/assets/vault.js').status_code == 404


def test_internal_errors_are_redacted(client,monkeypatch):
    async def broken():
        raise InternalError('/secret/private/identity.age sensitive stderr')
    monkeypatch.setattr(client.store,'list_folders',broken)
    response=post(client,'folders/list')
    assert response.status_code == 500
    assert response.json() == {'error':'Vault unavailable'}


def test_store_is_resolved_per_authenticated_request(client):
    alice = post(client, 'folders/list').json()['data']
    bob = client.post('/api/folders/list', json={}, headers={
        'X-Test-Account':'bob', 'X-Passage-Subject':'bob'}).json()['data']
    assert bob == [{'name':'bob-private-folder'}]
    assert bob != alice
    assert post(client, 'folders/list').json()['data'] == alice


def test_unexpected_store_failure_is_redacted(client, monkeypatch):
    async def broken():
        raise OSError('/private/vault/path')
    monkeypatch.setattr(client.store, 'list_folders', broken)
    response = post(client, 'folders/list')
    assert response.status_code == 500
    assert response.json() == {'error':'Vault unavailable'}
    assert response.headers['Cache-Control'] == 'no-store'


def test_credential_list_exposes_only_masked_tails(client):
    client.portal.call(client.store.add_folder, 'masked')
    client.portal.call(client.store.add_login, 'masked', 'long', 'fox', 'private-password-f514')
    client.portal.call(client.store.add_secret, 'masked', 'short', 'abcd')
    response = post(client, 'secrets/list', folder='masked')
    assert response.status_code == 200
    assert response.json()['data'] == [{'folder': 'masked', 'items': [
        {'name': 'long', 'masked': '••••f514'},
        {'name': 'short', 'masked': '••••'},
    ]}]
    assert 'private-password' not in response.text
    assert 'abcd' not in response.text
    assert 'username' not in response.text
    assert client.portal.call(client.store.list_secrets, 'masked') == [
        {'folder': 'masked', 'items': [{'name': 'long'}, {'name': 'short'}]}]


@pytest.mark.parametrize('late', [False, True])
def test_listing_skips_entries_removed_during_masking(client, monkeypatch, late):
    client.portal.call(client.store.add_secret, 'infra', 'gone', 'secret-gone')
    client.portal.call(client.store.add_secret, 'infra', 'kept', 'secret-kept')
    original = client.store.get_login
    async def disappearing(folder, item_name):
        if item_name == 'gone':
            await client.store.delete_secret(folder, item_name)
            if late:
                raise InternalError('age lost its input file')
        return await original(folder, item_name)
    monkeypatch.setattr(client.store, 'get_login', disappearing)
    response = post(client, 'secrets/list', folder='infra')
    assert response.status_code == 200
    assert response.json()['data'] == [{'folder': 'infra', 'items': [
        {'name': 'kept', 'masked': '••••kept'}]}]


def test_listing_preserves_real_decryption_failures(client, monkeypatch):
    client.portal.call(client.store.add_secret, 'infra', 'broken', 'secret-broken')
    async def broken(*args):
        raise InternalError('sensitive decryption diagnostic')
    monkeypatch.setattr(client.store, 'get_login', broken)
    response = post(client, 'secrets/list', folder='infra')
    assert response.status_code == 500
    assert response.json() == {'error': 'Vault unavailable'}


def test_listing_decrypts_with_bounded_parallelism(client, monkeypatch):
    import asyncio
    names = [str(i) for i in range(12)]
    active = peak = 0
    async def listing(folder):
        return [{'folder': folder, 'items': [{'name': name} for name in names]}]
    async def reading(folder, item_name):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.01)
            return {'password': 'secret-' + item_name}
        finally:
            active -= 1
    monkeypatch.setattr(client.store, 'list_secrets', listing)
    monkeypatch.setattr(client.store, 'get_login', reading)
    response = post(client, 'secrets/list', folder='infra')
    assert response.status_code == 200
    assert [item['name'] for item in response.json()['data'][0]['items']] == names
    assert peak == 4
    assert active == 0
    assert 'secret-' not in response.text
