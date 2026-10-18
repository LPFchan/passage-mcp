from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

import pytest

from passage_mcp.config import Config
from passage_mcp.identity import decode_subject, header_values, identity_from
from passage_mcp.store import AgeStore, ForbiddenError, InternalError, NotFoundError
from passage_mcp.tenancy import TenantManager, _publish_key
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


@pytest.mark.parametrize('bad', [None, '', '%', '%E', '%zz', '%FF', '%C0%AF', '%ED%A0%80', 'é', '😀'])
def test_subject_header_is_strict_ascii_percent_utf8(bad):
    assert decode_subject(bad) is None


def test_subject_header_decodes_once_without_normalization():
    for sub in ('여우😀 +%2F/', '42', 'café', 'cafe\u0301', '%FF', 'a\r\nb'):
        assert decode_subject(quote(sub, safe="~()*!.'-")) == sub
    assert decode_subject('a+b') == 'a+b'


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


@pytest.mark.parametrize('failure', ['partial-write', 'fsync', 'publish'])
def test_failed_key_publication_can_retry(setup, monkeypatch, failure):
    config, owner = setup
    manager = TenantManager(config, owner)
    name = hashlib.sha256(b'retry').hexdigest()
    key = config.tenant_keys_dir / (name + '.key')
    root = config.tenants_dir / name
    owner_before = config.identity_file.read_bytes()
    fdopen = os.fdopen

    class PartialWriter:
        def __init__(self, output): self.output = output
        def write(self, data):
            self.output.write(data[:16])
            self.output.flush()
            raise OSError('Injected disk full')

    @contextmanager
    def partial_fdopen(fd, mode):
        with fdopen(fd, mode) as output:
            yield PartialWriter(output) if mode == 'wb' else output

    def fail(*args): raise OSError('Injected filesystem failure')

    with monkeypatch.context() as patch:
        if failure == 'partial-write': patch.setattr(os, 'fdopen', partial_fdopen)
        elif failure == 'fsync': patch.setattr(os, 'fsync', fail)
        else: patch.setattr(os, 'link', fail)
        with pytest.raises(OSError): manager._provision(name)
    assert not key.exists()
    assert not root.exists()
    assert not list(config.tenant_keys_dir.glob('.key-*'))

    async def retry():
        store = await manager.get_store('retry')
        await store.add_folder('private')
        await store.add_secret('private', 'saved', 'retried')
        assert await store.get_secret('private', 'saved') == 'retried'
        before = key.read_bytes()
        again = await TenantManager(config, owner).get_store('retry')
        assert again._identity.read_bytes() == before
        assert await again.get_secret('private', 'saved') == 'retried'
    asyncio.run(retry())
    assert config.identity_file.read_bytes() == owner_before


def test_atomic_publication_never_overwrites_existing_key(setup):
    config, owner = setup
    TenantManager(config, owner)
    key = config.tenant_keys_dir / 'existing.key'
    key.write_bytes(config.identity_file.read_bytes())
    before = key.read_bytes()
    with pytest.raises(FileExistsError): _publish_key(key)
    assert key.read_bytes() == before
    assert not list(config.tenant_keys_dir.glob('.key-*'))


@pytest.mark.parametrize('completed', [False, True])
def test_malformed_existing_key_requires_repair(setup, completed):
    config, owner = setup
    manager = TenantManager(config, owner)
    name = hashlib.sha256(b'broken').hexdigest()
    if completed: manager._provision(name)
    root = config.tenants_dir / name
    before = {p.name: p.read_bytes() for p in root.iterdir()} if completed else {}
    key = config.tenant_keys_dir / (name + '.key')
    key.write_bytes(b'partial-private-key')
    with pytest.raises(InternalError, match='operator repair required') as error:
        manager._provision(name)
    assert 'partial-private-key' not in str(error.value)
    assert key.read_bytes() == b'partial-private-key'
    assert ({p.name: p.read_bytes() for p in root.iterdir()} if root.exists() else {}) == before
    assert root.exists() == completed


def test_wrong_valid_key_refused_and_correct_key_restored(setup):
    config, owner = setup
    async def scenario():
        manager = TenantManager(config, owner)
        store = await manager.get_store('restored')
        await store.add_folder('private')
        await store.add_secret('private', 'saved', 'previous-value')
        key = store._identity
        correct_key = key.read_bytes()
        wrong_key = config.identity_file.read_bytes()
        key.write_bytes(wrong_key)
        assert subprocess.run(['age-keygen', '-y', str(key)], check=True, capture_output=True).stdout
        before = {p.relative_to(store._root): p.read_bytes()
                  for p in store._root.rglob('*') if p.is_file()}
        for _ in range(2):
            with pytest.raises(InternalError, match='operator repair required') as error:
                await TenantManager(config, owner).get_store('restored')
            assert 'AGE-SECRET-KEY' not in str(error.value)
            assert key.read_bytes() == wrong_key
            assert {p.relative_to(store._root): p.read_bytes()
                    for p in store._root.rglob('*') if p.is_file()} == before
        key.write_bytes(correct_key)
        restored = await manager.get_store('restored')
        assert await restored.get_secret('private', 'saved') == 'previous-value'
        await restored.add_secret('private', 'new', 'new-value')
        assert await restored.get_secret('private', 'new') == 'new-value'
    asyncio.run(scenario())


@pytest.mark.parametrize('recovery', [False, True])
def test_existing_recipients_allow_comments_whitespace_and_recovery(setup, recovery):
    config, owner = setup
    async def scenario():
        manager = TenantManager(config, owner)
        store = await manager.get_store('recipients')
        recipients = store._root / '.age-recipients'
        pub = recipients.read_text().strip()
        recovery_pub = subprocess.run(['age-keygen', '-y', str(config.identity_file)],
                                      check=True, capture_output=True).stdout.decode().strip()
        contents = f'# private vault\n\n{recovery_pub if recovery else ""}\n{pub}\n'
        recipients.write_text(contents)
        key_before = store._identity.read_bytes()
        reopened = await manager.get_store('recipients')
        await reopened.add_folder('private')
        await reopened.add_secret('private', 'saved', 'readable')
        assert await reopened.get_secret('private', 'saved') == 'readable'
        assert recipients.read_text() == contents
        contents = f'  # private vault\n\n{recovery_pub if recovery else ""}\n  {pub}  \n'
        recipients.write_text(contents)
        reopened = await manager.get_store('recipients')
        assert await reopened.get_secret('private', 'saved') == 'readable'
        assert recipients.read_text() == contents
        assert reopened._identity.read_bytes() == key_before
    asyncio.run(scenario())


@pytest.mark.parametrize('failure', ['missing', 'unreadable', 'invalid-utf8', 'empty', 'invalid', 'comment', 'substring'])
def test_existing_invalid_recipients_require_repair(setup, monkeypatch, failure):
    config, owner = setup
    manager = TenantManager(config, owner)
    name = hashlib.sha256(b'broken-recipients').hexdigest()
    tenant = manager._provision(name)
    recipients = tenant.store_dir / '.age-recipients'
    pub = recipients.read_text().strip()
    if failure == 'missing': recipients.unlink()
    elif failure == 'invalid-utf8': recipients.write_bytes(b'\xff')
    elif failure == 'empty': recipients.write_text(' \n')
    elif failure == 'invalid': recipients.write_text('invalid-recipient')
    elif failure == 'comment': recipients.write_text(f'  # {pub}\n')
    elif failure == 'substring': recipients.write_text(f'{pub}extra\n')
    before = recipients.read_bytes() if recipients.exists() else None
    key_before = tenant.identity_file.read_bytes()
    read_text = Path.read_text
    def unreadable(path, *args, **kwargs):
        if path == recipients: raise PermissionError('sensitive filesystem details')
        return read_text(path, *args, **kwargs)
    if failure == 'unreadable': monkeypatch.setattr(Path, 'read_text', unreadable)
    with pytest.raises(InternalError, match='operator repair required') as error:
        manager._provision(name)
    assert 'sensitive filesystem details' not in str(error.value)
    assert tenant.identity_file.read_bytes() == key_before
    assert (recipients.read_bytes() if recipients.exists() else None) == before


def test_provision_multiprocess_race(setup):
    config, owner = setup
    TenantManager(config, owner)
    name = hashlib.sha256(b'multiprocess').hexdigest()
    settings = json.dumps(dict(store_dir=str(config.store_dir), identity_file=str(config.identity_file),
                               legacy_owner_sub='owner', tenants_dir=str(config.tenants_dir),
                               tenant_keys_dir=str(config.tenant_keys_dir)))
    script = '''
import json, sys
from passage_mcp.config import Config
from passage_mcp.store import AgeStore
from passage_mcp.tenancy import TenantManager
config = Config.from_dict(json.loads(sys.argv[1]))
TenantManager(config, AgeStore(config))._provision(sys.argv[2])
'''
    children = [subprocess.Popen([sys.executable, '-c', script, settings, name],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
    try:
        for child in children:
            _, stderr = child.communicate(timeout=30)
            assert child.returncode == 0, stderr.decode()
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate()
    assert len(list(config.tenants_dir.iterdir())) == 1
    assert len(list(config.tenant_keys_dir.glob('*.key'))) == 1
    assert not list(config.tenant_keys_dir.glob('.key-*'))
    async def validate():
        store = await TenantManager(config, owner).get_store('multiprocess')
        await store.validate()
    asyncio.run(validate())


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
