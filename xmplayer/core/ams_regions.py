from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import socket
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


AMS_BASES = tuple(f'https://{region}-ams.jftechws.com' for region in ('eu', 'sa', 'na', 'as'))
_HOSTS = {urlsplit(base).hostname for base in AMS_BASES} | {'ams.jftechws.com'}
SESSION_MAX_AGE = 15 * 60
SESSION_FIELDS = ('user_token', 'refresh_token', 'token_expires_utc', 'app_key', 'vendor',
                  'uuid', 'move_card', 'secret', 'dev_muserid', 'public_key', 'vms_key',
                  'ams_base', 'ams_login_base')


def normalize_ams_base(value: str) -> str:
    value = str(value or '').strip().rstrip('/')
    if not value:
        return ''
    if value in {'eu', 'sa', 'na', 'as'}:
        value = f'https://{value}-ams.jftechws.com'
    elif value in _HOSTS:
        value = f'https://{value}'
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.hostname not in _HOSTS or parsed.netloc != parsed.hostname
            or parsed.path or parsed.query or parsed.fragment):
        raise ValueError('ams_base must be eu, sa, na, as, or an official HTTPS AMS server')
    return f'https://{parsed.hostname}'


def ams_candidates(defaults, *, explicit: str = '', preferred: str = '', previous: str = '') -> list[str]:
    if explicit:
        return [normalize_ams_base(explicit)]
    candidates: list[str] = []
    for value in (preferred, previous, *defaults):
        try:
            base = normalize_ams_base(value)
        except ValueError:
            continue
        if base and base not in candidates:
            candidates.append(base)
    return candidates


def credential_identity(account: str, password: str, app_key: str, override: str = '') -> str:
    context = [socket.gethostname(), getpass.getuser(), account.strip(), password, app_key,
               normalize_ams_base(override)]
    return hashlib.sha256(json.dumps(context, ensure_ascii=False).encode('utf-8')).hexdigest()


class AmsCache:
    """Machine/account-bound session and region hints, never raw login requests."""
    def __init__(self, identity: str, path: Path | None = None) -> None:
        self.identity = identity
        self.path = path or Path(__file__).resolve().parents[1] / 'config' / 'ams_cache.json'

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
            if isinstance(data, dict) and data.get('version') == 1 and data.get('identity') == self.identity:
                return data
        except (OSError, ValueError):
            pass
        return {}

    def _write(self, data: dict[str, Any]) -> None:
        temporary: Path | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data.update(version=1, identity=self.identity)
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.path.parent,
                                             prefix=self.path.name + '.', suffix='.tmp', delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(data, stream, ensure_ascii=False)
            os.replace(temporary, self.path)
        except OSError:
            pass  # A read-only checkout must not prevent cloud access.
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def preferred_region(self, serial: str = '') -> str:
        data = self._read()
        devices = data.get('devices') if isinstance(data.get('devices'), dict) else {}
        try:
            return normalize_ams_base(devices.get(serial) or data.get('region') or '')
        except ValueError:
            return ''

    def remember_region(self, base: str, serial: str = '') -> None:
        data = self._read()
        data['region'] = normalize_ams_base(base)
        devices = data.get('devices') if isinstance(data.get('devices'), dict) else {}
        if serial:
            devices[serial] = data['region']
        data['devices'] = devices
        self._write(data)

    def load_session(self) -> dict[str, Any] | None:
        data = self._read()
        try:
            now = time.time()
            if not (0 <= now - float(data.get('saved_at', 0)) <= SESSION_MAX_AGE
                    and float(data.get('expires_at', 0)) > now + 30):
                return None
            session = data.get('session')
            if not isinstance(session, dict) or not all(session.get(key) for key in ('user_token', 'app_key', 'uuid', 'secret', 'move_card')):
                return None
            result = {key: session[key] for key in SESSION_FIELDS if key in session}
            if any(not isinstance(value, str) for key, value in result.items() if key != 'move_card'):
                return None
            result['move_card'] = int(result['move_card'])
            if result['move_card'] <= 0:
                return None
            for key in ('ams_base', 'ams_login_base'):
                result[key] = normalize_ams_base(str(result.get(key) or ''))
            return result
        except (ValueError, TypeError):
            return None

    def save_session(self, session, *, fresh: bool = False) -> None:
        data = self._read()
        now = time.time()
        expires_at = now + SESSION_MAX_AGE
        try:
            segment = session.user_token.split('.')[1]
            claims = json.loads(base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4)))
            if isinstance(claims, dict):
                expires_at = min(expires_at, float(claims.get('exp', expires_at)))
        except (IndexError, ValueError, TypeError):
            pass
        if not fresh and isinstance(data.get('session'), dict) and data['session'].get('user_token') == session.user_token:
            now = float(data.get('saved_at', now))
            expires_at = min(expires_at, float(data.get('expires_at', expires_at)))
        data.update(saved_at=now, expires_at=expires_at,
                    session={key: getattr(session, key, '') for key in SESSION_FIELDS})
        self._write(data)
