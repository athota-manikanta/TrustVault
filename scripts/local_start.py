"""Convenience launcher for local evaluation only; do not use for deployment."""
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
CONFIG = BASE / '.local-demo-credentials.json'
DB = BASE / 'trustvault.db'

if not CONFIG.exists():
    if DB.exists():
        print('\nIMPORTANT: An existing trustvault.db was found without demo credentials.')
        print('To avoid changing existing accounts, this launcher will not create new passwords.')
        print('If you do not need the previous local data, close this window,')
        print('rename trustvault.db to trustvault-old.db, and start again.')
        sys.exit(1)
    config = {
        'TRUSTVAULT_SECRET': secrets.token_urlsafe(48),
        'SEED_ADMIN_PASSWORD': secrets.token_urlsafe(18),
        'SEED_OWNER_PASSWORD': secrets.token_urlsafe(18),
        'SEED_VIEWER_PASSWORD': secrets.token_urlsafe(18),
        'SEED_OTHER_PASSWORD': secrets.token_urlsafe(18),
    }
    CONFIG.write_text(json.dumps(config, indent=2), encoding='utf-8')
else:
    config = json.loads(CONFIG.read_text(encoding='utf-8'))

os.environ.update(config)
os.chdir(BASE)
print('\nCreating or verifying demo accounts...')
result = subprocess.run([sys.executable, '-m', 'scripts.seed'], check=False)
if result.returncode:
    sys.exit(result.returncode)
print('\n=== YOUR LOCAL DEMO LOGIN DETAILS ===')
for username, key in [('admin_demo','SEED_ADMIN_PASSWORD'),('owner_demo','SEED_OWNER_PASSWORD'),
                      ('viewer_demo','SEED_VIEWER_PASSWORD'),('other_demo','SEED_OTHER_PASSWORD')]:
    print(f'Username: {username}  Password: {config[key]}')
print('\nThese are ONLY for local practice. Do not upload or publish them.')
print('Open this address in Chrome: http://127.0.0.1:8000')
print('To stop, press Ctrl+C in this window.\n', flush=True)
sys.exit(subprocess.call([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000']))
