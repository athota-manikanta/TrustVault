import json

import httpx
import pytest

from app.storage import SupabaseBlobStorage, create_storage


class FakeSupabase:
    def __init__(self):
        self.objects = {}
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)

        if request.method == 'GET' and '/bucket/' in request.url.path:
            return httpx.Response(200, json={'id': 'private-trustvault', 'public': False}, request=request)
        if request.method == 'POST':
            key = request.url.path.rsplit('/', 1)[-1]
            bucket = request.url.path.split('/')[-2]
            self.objects[(bucket, key)] = request.content
            return httpx.Response(200, json={'Key': key}, request=request)
        if request.method == 'GET':
            key = request.url.path.rsplit('/', 1)[-1]
            bucket = request.url.path.split('/')[-2]
            content = self.objects.get((bucket, key))
            if content is None:
                return httpx.Response(404, json={'error': 'Object not found'}, request=request)
            return httpx.Response(200, content=content, request=request)
        if request.method == 'DELETE':
            bucket = request.url.path.rsplit('/', 1)[-1]
            body = json.loads(request.content)
            for prefix in body['prefixes']:
                self.objects.pop((bucket, prefix), None)
            return httpx.Response(200, json={'message': 'deleted'}, request=request)
        return httpx.Response(405, request=request)


def make_storage(handler, api_key='server-only-key'):
    storage = SupabaseBlobStorage.__new__(SupabaseBlobStorage)
    storage.bucket = 'private-trustvault'
    headers = {'apikey': api_key}
    if not api_key.startswith('sb_secret_'):
        headers['Authorization'] = f'Bearer {api_key}'
    storage.client = httpx.Client(
        base_url='https://project.supabase.co/storage/v1/',
        headers=headers,
        transport=httpx.MockTransport(handler),
    )
    return storage


def test_supabase_blob_storage_round_trips_private_object():
    fake = FakeSupabase()
    storage = make_storage(fake)
    key = '00000000-0000-0000-0000-000000000001'

    storage.put(key, b'secret content')
    assert storage.get(key) == b'secret content'
    assert storage.get('00000000-0000-0000-0000-000000000002') is None
    storage.delete(key)
    assert storage.get(key) is None

    upload_request = fake.requests[0]
    assert upload_request.url.path == (
        '/storage/v1/object/private-trustvault/00000000-0000-0000-0000-000000000001'
    )
    assert upload_request.headers['apikey'] == 'server-only-key'
    assert upload_request.headers['authorization'] == 'Bearer server-only-key'
    assert upload_request.headers['x-upsert'] == 'false'
    assert all('sign' not in request.url.path for request in fake.requests)


def test_supabase_secret_key_is_not_sent_as_bearer_token():
    fake = FakeSupabase()
    storage = make_storage(fake, 'sb_secret_example')

    storage.put('00000000-0000-0000-0000-000000000001', b'secret content')

    request = fake.requests[0]
    assert request.headers['apikey'] == 'sb_secret_example'
    assert 'authorization' not in request.headers


def test_supabase_blob_storage_rejects_non_uuid_keys():
    storage = make_storage(FakeSupabase())
    with pytest.raises(ValueError):
        storage.get('../outside')


def test_supabase_storage_requires_https_and_credentials():
    with pytest.raises(ValueError, match='HTTPS'):
        SupabaseBlobStorage('http://project.supabase.co', 'server-key', 'private')
    with pytest.raises(ValueError, match='secret API key'):
        SupabaseBlobStorage('https://project.supabase.co', '', 'private')


def test_supabase_bucket_preflight_requires_private_bucket():
    fake = FakeSupabase()
    storage = make_storage(fake)
    storage.require_private_bucket()
    assert fake.requests[0].url.path == '/storage/v1/bucket/private-trustvault'

    def public_bucket(request):
        return httpx.Response(200, json={'id': 'private-trustvault', 'public': True}, request=request)

    public_storage = make_storage(public_bucket)
    with pytest.raises(RuntimeError, match='must be private'):
        public_storage.require_private_bucket()

    def denied_bucket(request):
        return httpx.Response(
            403,
            json={'message': 'secret-key-value must not appear'},
            request=request,
        )

    denied_storage = make_storage(denied_bucket)
    with pytest.raises(RuntimeError) as error:
        denied_storage.require_private_bucket()
    assert 'secret-key-value' not in str(error.value)


def test_create_storage_requires_supabase_settings(monkeypatch):
    monkeypatch.setenv('TRUSTVAULT_STORAGE_BACKEND', 'supabase')
    monkeypatch.delenv('SUPABASE_URL', raising=False)
    monkeypatch.delenv('SUPABASE_SECRET_KEY', raising=False)
    monkeypatch.delenv('SUPABASE_STORAGE_BUCKET', raising=False)

    with pytest.raises(RuntimeError, match='SUPABASE_URL'):
        create_storage()
