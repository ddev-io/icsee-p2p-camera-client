from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from ..core.ams_regions import normalize_ams_base


@dataclass(slots=True)
class WindowConfig:
    width: int = 1440
    height: int = 900
    start_fullscreen: bool = False


@dataclass(slots=True)
class PathsConfig:
    logs_dir: Path
    screenshots_dir: Path


@dataclass(slots=True)
class MonitorConfig:
    project_root: Path
    config_path: Path
    device_id: str
    device_name: str
    cloud_login_file: Path
    runtime_mode: str
    controller_profile: str
    agent_client_id: str
    default_quality: str
    ffmpeg_path: str
    capture_seconds: float
    max_frames: int
    attempts: int
    playback_fps: float
    display_mode: str
    window: WindowConfig
    paths: PathsConfig
    ams_base: str = ''
    connection_mode: str = 'account'
    cloud_id: str = ''
    device_username: str = 'admin'
    device_password: str = field(default='', repr=False)


def _resolve_path(project_root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (project_root / path).resolve()


def _resolve_ffmpeg(project_root: Path, value: str) -> str:
    if value != 'ffmpeg':
        return str(_resolve_path(project_root, value))
    if shutil.which('ffmpeg'):
        return 'ffmpeg'
    for candidate in ('ffmpeg/ffmpeg.exe', 'ffmpeg/bin/ffmpeg.exe'):
        path = project_root / candidate
        if path.is_file():
            return str(path)
    return 'ffmpeg'


def validate_cloud_login_file(path: Path) -> str | None:
    if not path.exists():
        return f'cloud login file not found: {path}'
    lines = [line.strip() for line in path.read_text(encoding='utf-8-sig', errors='ignore').splitlines() if line.strip()]
    if len(lines) < 2:
        return f'cloud login file must contain login and password: {path}'
    login = lines[0]
    password = lines[1]
    placeholder_pairs = {
        ('your_login', 'your_password'),
        ('login', 'password'),
        ('email', 'password'),
    }
    if (login, password) in placeholder_pairs:
        return f'cloud login file still contains placeholder credentials: {path}'
    return None


def validate_connection_credentials(config: MonitorConfig) -> str | None:
    if getattr(config, 'connection_mode', 'account') == 'cloud_id':
        from ..core.cloud_id import CloudIdError, validate_cloud_id
        try:
            validate_cloud_id(config.device_id)
        except CloudIdError:
            return 'Enter the camera Cloud ID'
        if not config.device_username.strip():
            return 'Enter the camera username'
        return None  # An empty camera password is valid.
    return validate_cloud_login_file(config.cloud_login_file)


def load_monitor_config(config_path: str | Path | None = None) -> MonitorConfig:
    project_root = Path(__file__).resolve().parents[2]
    if config_path is None:
        local_config = project_root / 'desktop_monitor.local.json'
        resolved_config = local_config if local_config.exists() else project_root / 'desktop_monitor.json'
    else:
        resolved_config = _resolve_path(project_root, str(config_path))
    if not resolved_config.exists():
        raise FileNotFoundError(f'config not found: {resolved_config}')
    raw = json.loads(resolved_config.read_text(encoding='utf-8-sig'))
    connection_mode = str(raw.get('connection_mode') or 'account').strip()
    if connection_mode not in {'account', 'cloud_id'}:
        raise ValueError('connection_mode must be account or cloud_id')
    window_raw: dict[str, Any] = raw.get('window') or {}
    paths_raw: dict[str, Any] = raw.get('paths') or {}
    window = WindowConfig(
        width=int(window_raw.get('width') or 1440),
        height=int(window_raw.get('height') or 900),
        start_fullscreen=bool(window_raw.get('start_fullscreen', False)),
    )
    paths = PathsConfig(
        logs_dir=_resolve_path(project_root, str(paths_raw.get('logs_dir') or 'logs')),
        screenshots_dir=_resolve_path(project_root, str(paths_raw.get('screenshots_dir') or 'screenshots')),
    )
    paths.screenshots_dir.mkdir(parents=True, exist_ok=True)
    cfg = MonitorConfig(
        project_root=project_root,
        config_path=resolved_config,
        device_id=str((raw.get('cloud_id') or raw.get('device_id') or '') if connection_mode == 'cloud_id'
                      else raw.get('device_id') or '').strip(),
        device_name=str(raw.get('device_name') or 'Camera').strip() or 'Camera',
        cloud_login_file=_resolve_path(project_root, str(raw.get('cloud_login_file') or 'login.txt')),
        runtime_mode=str(raw.get('runtime_mode') or 'experimental_current').strip() or 'experimental_current',
        controller_profile=str(raw.get('controller_profile') or 'app_reference_first_6611').strip() or 'app_reference_first_6611',
        agent_client_id=str(raw.get('agent_client_id') or '').strip(),
        default_quality=str(raw.get('default_quality') or 'sd').strip().lower() or 'sd',
        ffmpeg_path=_resolve_ffmpeg(project_root, str(raw.get('ffmpeg_path') or 'ffmpeg').strip()),
        capture_seconds=max(float(raw.get('capture_seconds') or 40.0), 6.0),
        max_frames=max(int(raw.get('max_frames') or 1024), 64),
        attempts=max(int(raw.get('attempts') or 3), 1),
        playback_fps=max(float(raw.get('playback_fps') or 12.0), 1.0),
        display_mode=str(raw.get('display_mode') or 'stacked_split').strip().lower() or 'stacked_split',
        window=window,
        paths=paths,
        ams_base=normalize_ams_base(raw.get('ams_base') or ''),
        connection_mode=connection_mode,
        cloud_id=str(raw.get('cloud_id') or '').strip(),
        device_username=str(raw.get('device_username') or 'admin').strip(),
        device_password=str(raw.get('device_password') or ''),
    )
    if cfg.default_quality not in {'sd', 'hd'}:
        raise ValueError('default_quality must be sd or hd')
    if cfg.agent_client_id and (len(cfg.agent_client_id) != 26 or not cfg.agent_client_id.startswith('c_')):
        raise ValueError('agent_client_id must be an iCSee AgentProtocol client id like c_...')
    if cfg.display_mode not in {'raw', 'stacked_split'}:
        raise ValueError('display_mode must be raw or stacked_split')
    return cfg
