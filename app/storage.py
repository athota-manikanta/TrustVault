"""Private document blob storage backed by local files or Supabase Storage."""
import os
import uuid
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx


class LocalBlobStorage:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != 'nt':
            os.chmod(self.root, 0o700)

    def _path(self, key: str) -> Path:
        safe_key = str(uuid.UUID(key))
        path = (self.root / safe_key).resolve()
        if path.parent != self.root:
            raise ValueError('Invalid storage key')
        return path

    def put(self, key: str, content: bytes) -> None:
        path = self._path(key)
        with open(path, 'xb') as file:
            file.write(content)
        if os.name != 'nt':
            os.chmod(path, 0o600)

    def get(self, key: str) -> bytes | None:
        path = self._path(key)
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)


class SupabaseBlobStorage:
    def __init__(self, url: str, api_key: str, bucket: str, timeout: float = 30.0):
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https' or not parsed_url.netloc:
            raise ValueError('SUPABASE_URL must be an HTTPS URL')
        if not api_key or not bucket:
            raise ValueError('Supabase secret API key and bucket are required')

        self.bucket = quote(bucket, safe='')
        headers = {'apikey': api_key}
        if not api_key.startswith('sb_secret_'):
            headers['Authorization'] = f'Bearer {api_key}'
        self.client = httpx.Client(
            base_url=f'{url.rstrip("/")}/storage/v1/',
            headers=headers,
            timeout=timeout,
        )

    def require_private_bucket(self) -> None:
        response = self.client.get(f'bucket/{self.bucket}')
        if response.status_code == 404:
            raise RuntimeError('Configured Supabase Storage bucket was not found.')
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError:
            raise RuntimeError(
                'Supabase Storage bucket preflight failed; check the URL and secret key.'
            ) from None
        try:
            is_public = response.json().get('public')
        except (ValueError, AttributeError):
            raise RuntimeError('Supabase Storage returned invalid bucket metadata.') from None
        if is_public is not False:
            raise RuntimeError('Configured Supabase Storage bucket must be private.')

    @staticmethod
    def _key(key: str) -> str:
        return str(uuid.UUID(key))

    def _object_path(self, key: str) -> str:
        return f'object/{self.bucket}/{self._key(key)}'

    def put(self, key: str, content: bytes) -> None:
        response = self.client.post(
            self._object_path(key),
            content=content,
            headers={
                'Content-Type': 'application/octet-stream',
                'x-upsert': 'false',
            },
        )
        response.raise_for_status()

    def get(self, key: str) -> bytes | None:
        response = self.client.get(self._object_path(key))
        if response.status_code == 404:
            return None
        if response.status_code == 400 and 'not found' in response.text.lower():
            return None
        response.raise_for_status()
        return response.content

    def delete(self, key: str) -> None:
        response = self.client.request(
            'DELETE',
            f'object/{self.bucket}',
            json={'prefixes': [self._key(key)]},
        )
        response.raise_for_status()


def create_storage():
    backend = os.environ.get('TRUSTVAULT_STORAGE_BACKEND', 'local').strip().lower()
    if backend == 'local':
        root = Path(os.environ.get('TRUSTVAULT_STORAGE', 'private_storage')).resolve()
        return LocalBlobStorage(root), root
    if backend == 'supabase':
        url = os.environ.get('SUPABASE_URL', '').strip()
        api_key = os.environ.get('SUPABASE_SECRET_KEY', '').strip()
        bucket = os.environ.get('SUPABASE_STORAGE_BUCKET', '').strip()
        if not url or not api_key or not bucket:
            raise RuntimeError(
                'SUPABASE_URL, SUPABASE_SECRET_KEY, and '
                'SUPABASE_STORAGE_BUCKET are required when '
                'TRUSTVAULT_STORAGE_BACKEND=supabase'
            )
        storage = SupabaseBlobStorage(url, api_key, bucket)
        return storage, None
    raise RuntimeError('TRUSTVAULT_STORAGE_BACKEND must be local or supabase')
