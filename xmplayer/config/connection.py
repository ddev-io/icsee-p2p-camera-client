"""Persist the selected connection in the user's local configuration."""
import json
from pathlib import Path

from .loader import MonitorConfig, validate_cloud_login_file
from ..core.cloud_id import validate_cloud_id, CloudIdError


def read_account_credentials(path: Path) -> tuple[str, str]:
    try:
        if validate_cloud_login_file(path):
            return '', ''
        lines = path.read_text(encoding='utf-8-sig').splitlines()
    except OSError:
        return '', ''
    return (lines[0].strip() if lines else '', lines[1] if len(lines) > 1 else '')


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    try:
        temporary.write_text(text, encoding='utf-8')
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def save_connection_settings(config: MonitorConfig, *, mode: str,
                             account: str = '', account_password: str = '',
                             cloud_id: str = '', device_username: str = 'admin',
                             device_password: str = '') -> Path:
    raw = json.loads(config.config_path.read_text(encoding='utf-8-sig'))
    if not isinstance(raw, dict):
        raise ValueError('The configuration must contain an object')
    if mode == 'cloud_id':
        try:
            serial = validate_cloud_id(cloud_id)
        except CloudIdError:
            raise ValueError('Enter a valid camera Cloud ID') from None
        username = device_username.strip()
        if not username:
            raise ValueError('Enter the camera username')
        raw.update(connection_mode=mode, cloud_id=serial, device_id=serial,
                   device_username=username, device_password=device_password)
    elif mode == 'account':
        account = account.strip()
        if not account or not account_password:
            raise ValueError('Enter the app account and password')
        old_account = read_account_credentials(config.cloud_login_file)
        if config.connection_mode != 'account' or old_account != (account, account_password):
            raw['device_id'] = ''  # Discover the selected account's camera.
        _write_atomic(config.cloud_login_file, f'{account}\n{account_password}\n')
        raw['connection_mode'] = mode
    else:
        raise ValueError('Choose Account or Cloud ID')
    destination = config.config_path.with_name('desktop_monitor.local.json')
    _write_atomic(destination, json.dumps(raw, ensure_ascii=False, indent=2) + '\n')
    return destination
