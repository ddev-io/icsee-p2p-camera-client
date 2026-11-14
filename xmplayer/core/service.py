from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from ..config.loader import MonitorConfig, validate_cloud_login_file, validate_connection_credentials
from . import legacy_api, legacy_cli
from .ams_regions import credential_identity

StatusCallback = Callable[[str, str], None]


class MonitorCaptureError(RuntimeError):
    pass


class MonitorCancelled(RuntimeError):
    pass


TOKEN_CACHE_MAX_AGE_SECONDS = 24 * 60 * 60
MONITOR_JSON_LOGS_ENABLED = False
PLAYBACK_BY_TIME_DUMMY_FILE = '/idea0/2015-10-20/001/00.00.00-00.00.09[H][@bff][0].h264'
PLAYBACK_END_TIME_MODE = 'recording_end'
OPFILEQUERY_PAGE_CAP_HINT = 64


def _cache_machine_id() -> str:
    name = str(os.environ.get('COMPUTERNAME') or socket.gethostname() or '').strip().lower()
    user = str(os.environ.get('USERNAME') or os.environ.get('USER') or '').strip().lower()
    return f'{name}/{user}' if user else name


@dataclass(slots=True)
class CaptureArtifacts:
    run_json_path: Path
    result: dict[str, Any]
    quality: str
    attempt_count: int


@dataclass(slots=True)
class MonitorMessage:
    title: str
    timestamp: str
    detail: str = ""
    image_url: str = ""
    image_urls: list[str] = field(default_factory=list)
    raw: dict[str, Any] | None = None


@dataclass(slots=True)
class RecordingItem:
    title: str
    start_time: str
    end_time: str
    duration_seconds: int = 0
    file_name: str = ""
    file_length: int = 0
    channel: int = 0
    raw: dict[str, Any] | None = None


def _timestamp_slug() -> str:
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def _disabled_log_path(config: MonitorConfig, prefix: str, quality: str) -> Path:
    return config.paths.logs_dir / f'{prefix}_{quality}_logging_disabled.json'


def _emit_status(callback: StatusCallback | None, state: str, detail: str) -> None:
    if callback is not None:
        callback(state, detail)


def _emit_progress(callback: Callable[[str], None] | None, detail: str) -> None:
    if callback is not None:
        callback(' '.join(str(detail or '').split()))


class _StartupProgress:
    def __init__(self, callback: StatusCallback | None, *, total_steps: int = 30) -> None:
        self.callback = callback
        self.total_steps = max(int(total_steps), 1)
        self.current_step = 0
        self.state = 'Connecting'

    def set_state(self, state: str) -> None:
        self.state = state or 'Connecting'

    def emit(self, detail: str) -> None:
        if self.callback is None:
            return
        label = ' '.join(str(detail or '').split())
        if not label:
            return
        self.current_step += 1
        total = max(self.total_steps, self.current_step + 4)
        _emit_status(self.callback, self.state, f'progress|{self.current_step}|{total}|{label}')


def _raise_if_cancelled(stop_event: threading.Event | None) -> None:
    if stop_event is not None and stop_event.is_set():
        raise MonitorCancelled('capture cancelled')


def _quality_to_handoff_stream_type(quality: str) -> str:
    return 'Main' if str(quality).strip().lower() == 'hd' else 'Extra1'


def _agent_client_token(config: MonitorConfig) -> str:
    configured = str(getattr(config, 'agent_client_id', '') or '').strip()
    use_config = str(os.environ.get('XMPLAYER_USE_CONFIG_AGENT_CLIENT_ID') or '').strip().lower() in {
        '1',
        'true',
        'yes',
        'on',
    }
    if configured and use_config:
        return configured
    return legacy_api.get_agent_client_uuid().strip()


def _result_has_second_video(result: dict[str, Any]) -> bool:
    enc_probe = result.get('tcp_encrypted_probe') if isinstance(result.get('tcp_encrypted_probe'), dict) else {}
    runs = list(result.get('plain_handoff_runs') or [])
    runs.extend(enc_probe.get('plain_handoff_runs') or [])
    nested_probe = enc_probe.get('plain_handoff_probe')
    if isinstance(nested_probe, dict) and nested_probe:
        runs.append({'probe': nested_probe})
    for run in runs:
        probe = run.get('probe') or {}
        frames = probe.get('frames') or {}
        if int(frames.get('data') or 0) > 0:
            return True
        if probe.get('status') == 'ok' and (frames.get('data_frames') or []):
            return True
    return False


def _score_result(result: dict[str, Any]) -> tuple[int, int, int, int]:
    enc_probe = result.get('tcp_encrypted_probe') if isinstance(result.get('tcp_encrypted_probe'), dict) else {}
    runs = list(result.get('plain_handoff_runs') or [])
    runs.extend(enc_probe.get('plain_handoff_runs') or [])
    nested_probe = enc_probe.get('plain_handoff_probe')
    if isinstance(nested_probe, dict) and nested_probe:
        runs.append({'probe': nested_probe})
    plain_runs = len(runs)
    second_status_score = 0
    second_data_frames = 0
    encrypted_control = int((((result.get('tcp_encrypted_probe') or {}).get('frames') or {}).get('control') or 0))
    for run in runs:
        probe = run.get('probe') or {}
        frames = probe.get('frames') or {}
        second_data_frames = max(second_data_frames, len(frames.get('data_frames') or []))
        if probe.get('status') == 'ok':
            second_status_score = max(second_status_score, 2)
        elif probe:
            second_status_score = max(second_status_score, 1)
    return (second_data_frames, second_status_score, plain_runs, encrypted_control)


def _frame_counts(probe: dict[str, Any]) -> dict[str, Any]:
    frames = probe.get('frames') if isinstance(probe.get('frames'), dict) else {}
    out = {
        'total': int(frames.get('total') or 0),
        'control': int(frames.get('control') or 0),
        'data': int(frames.get('data') or 0),
        'data_total_bytes': int(frames.get('data_total_bytes') or 0),
        'raw_total_bytes': int(frames.get('raw_total_bytes') or 0),
    }
    for key in (
        'exit_reason',
        'duration_seconds',
        'media_span_seconds',
        'first_data_at_seconds',
        'last_data_at_seconds',
        'last_chunk_at_seconds',
    ):
        if key in frames:
            out[key] = frames.get(key)
    return out


def _short_payload_label(text: str) -> str:
    if not text:
        return ''
    if '"Name":"KeepAlive"' in text:
        return 'KeepAlive'
    if '"Name":"OPMonitor"' in text:
        if '"Action":"Start"' in text:
            return 'OPMonitor Start'
        if '"Action":"Stop"' in text:
            return 'OPMonitor Stop'
        return 'OPMonitor'
    if '"Name":"OPPlayBack"' in text:
        if '"Action":"Claim"' in text:
            return 'OPPlayBack Claim'
        if '"Action":"SetIntelligentType"' in text:
            return 'OPPlayBack SetIntelligentType'
        if '"Action":"Start"' in text:
            return 'OPPlayBack Start'
        if '"Action":"Stop"' in text:
            return 'OPPlayBack Stop'
        return 'OPPlayBack'
    if '"Name":"' in text:
        name = text.split('"Name":"', 1)[1].split('"', 1)[0]
        return name[:48]
    if '"UploadData"' in text:
        return 'UploadData Stop' if '"Stop":true' in text or '"Stop": true' in text else 'UploadData'
    return ''


def _summarize_followups(followups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not followups:
        return []
    started_at = next((float(item.get('sent_at') or 0.0) for item in followups if item.get('sent_at')), 0.0)
    summary: list[dict[str, Any]] = []
    for item in followups:
        sent_at = float(item.get('sent_at') or 0.0)
        entry = {
            'dt': round(sent_at - started_at, 3) if started_at and sent_at else None,
            'cmd': f"0x{int(item.get('cmd') or 0):04x}",
            'msg_id': int(item.get('msg_id') or 0),
        }
        label = _short_payload_label(str(item.get('plain_payload_text') or ''))
        if label:
            entry['label'] = label
        summary.append(entry)
    return summary


def _summarize_handoff_probe(probe: dict[str, Any]) -> dict[str, Any]:
    if not probe:
        return {}
    opmonitor = probe.get('opmonitor') if isinstance(probe.get('opmonitor'), dict) else {}
    response = opmonitor.get('response') if isinstance(opmonitor.get('response'), dict) else {}
    keepalives = opmonitor.get('keepalives') if isinstance(opmonitor.get('keepalives'), list) else []
    out: dict[str, Any] = {
        'status': probe.get('status'),
        'ret': response.get('Ret'),
        'frames': _frame_counts(probe),
        'keepalives': len(keepalives),
    }
    if probe.get('error'):
        out['error'] = probe.get('error')
    controller_summary = probe.get('controller_summary') if isinstance(probe.get('controller_summary'), dict) else {}
    if controller_summary:
        out['controller_status'] = controller_summary.get('status')
    return out


def _short_error(value: Any, limit: int = 180) -> str:
    text = str(value or '').strip().replace('\r', ' ').replace('\n', ' ')
    if len(text) > limit:
        return text[: limit - 3] + '...'
    return text


def _summarize_pub_status(result: dict[str, Any]) -> dict[str, Any]:
    status_query = result.get('status_query') if isinstance(result.get('status_query'), dict) else {}
    parsed = status_query.get('parsed') if isinstance(status_query.get('parsed'), dict) else {}
    body = parsed.get('body') if isinstance(parsed.get('body'), list) else []
    entry = body[0] if body and isinstance(body[0], dict) else {}
    server_ip = str(entry.get('ServerIP') or '').strip()
    server_port = str(entry.get('ServerPort') or '').strip()
    out: dict[str, Any] = {
        'ok': bool(status_query.get('ok')),
        'http_status': status_query.get('status'),
        'server': f'{server_ip}:{server_port}' if server_ip and server_port else '',
        'device_status': str(entry.get('Status') or '').strip(),
    }
    if status_query.get('error'):
        out['error'] = _short_error(status_query.get('error'))
    parsed_error = str(parsed.get('error_string') or parsed.get('error_num') or '').strip()
    if parsed_error and parsed_error.lower() not in {'success ok', '200'}:
        out['parsed_error'] = _short_error(parsed_error)
    return out


def _summarize_agent_protocol(result: dict[str, Any]) -> dict[str, Any]:
    agent_http = result.get('agent_http') if isinstance(result.get('agent_http'), dict) else {}
    attempts = agent_http.get('attempts') if isinstance(agent_http.get('attempts'), list) else []
    selected = agent_http.get('selected') if isinstance(agent_http.get('selected'), dict) else {}
    parsed = selected.get('parsed') if isinstance(selected.get('parsed'), dict) else {}
    errors = []
    responses = []
    # Bound the report, but always retain the selected response even if a
    # successful retry appears after the first 32 HTTP attempts.
    rows = list(enumerate(attempts, 1))
    if selected and not any(attempt == selected for _, attempt in rows):
        rows.append((len(attempts) + 1, selected))
    for index, attempt in rows:
        if not isinstance(attempt, dict):
            continue
        diagnostic = attempt.get('response_diagnostics')
        if not isinstance(diagnostic, dict):
            continue
        error = diagnostic.get('transport_error')
        if not error and str(diagnostic.get('error_num') or '') not in {'', '0', '100', '200'}:
            error = diagnostic.get('error_string') or f"AgentProtocol ErrorNum={diagnostic['error_num']}"
        if error and len(errors) < 3:
            errors.append(error)
        is_selected = bool(selected and attempt == selected)
        if len(responses) < 32 or is_selected:
            responses.append({
                'index': index, 'selected': is_selected,
                'http_status': attempt.get('status'), 'http_ok': bool(attempt.get('ok')),
                **diagnostic,
            })
    out: dict[str, Any] = {
        'attempts': len(attempts),
        'selected': bool(parsed.get('agent_server_ip') and parsed.get('agent_server_port')),
        'agent_server': (
            f"{parsed.get('agent_server_ip')}:{parsed.get('agent_server_port')}"
            if parsed.get('agent_server_ip') and parsed.get('agent_server_port')
            else ''
        ),
        'responses': responses,
        'responses_omitted': max(len(attempts) - len(responses), 0),
    }
    if errors:
        out['errors'] = errors
    return out


def _summarize_agent_server(result: dict[str, Any]) -> dict[str, Any]:
    server = result.get('agent_server') if isinstance(result.get('agent_server'), dict) else {}
    agent_http = result.get('agent_http') if isinstance(result.get('agent_http'), dict) else {}
    selected = agent_http.get('selected') if isinstance(agent_http.get('selected'), dict) else {}
    diagnostic = selected.get('response_diagnostics')
    ip = str(server.get('ip') or '').strip()
    port = int(server.get('port') or 0)
    return {
        'server': f'{ip}:{port}' if ip and port else '',
        'protocol_mode': diagnostic.get('protocol_mode', '') if isinstance(diagnostic, dict) else '',
    }


def _split_host_port(value: Any) -> tuple[str, str] | None:
    text = str(value or '').strip()
    if not text or ':' not in text:
        return None
    host, port = text.rsplit(':', 1)
    host = host.strip()
    port = port.strip()
    if not host or not port.isdigit():
        return None
    return host, port


def _extract_status_server(result: dict[str, Any]) -> tuple[str, str] | None:
    pub_status = result.get('pub_status') if isinstance(result.get('pub_status'), dict) else {}
    from_summary = _split_host_port(pub_status.get('server'))
    if from_summary:
        return from_summary
    status_query = result.get('status_query') if isinstance(result.get('status_query'), dict) else {}
    parsed = status_query.get('parsed') if isinstance(status_query.get('parsed'), dict) else {}
    body = parsed.get('body') if isinstance(parsed.get('body'), list) else []
    for entry in body:
        if not isinstance(entry, dict):
            continue
        host = str(entry.get('ServerIP') or '').strip()
        port = str(entry.get('ServerPort') or '').strip()
        if host and port.isdigit():
            return host, port
    return None


def _relay_cache_path(config: MonitorConfig) -> Path:
    path = config.project_root / 'xmplayer' / 'config' / 'relay_cache.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _load_relay_cache_servers(config: MonitorConfig, *, limit: int) -> list[tuple[str, str]]:
    path = _relay_cache_path(config)
    if not path.exists():
        return []
    try:
        cache = json.loads(path.read_text(encoding='utf-8-sig'))
    except Exception:
        return []
    rows = cache.get('status_servers') if isinstance(cache, dict) else []
    if not isinstance(rows, list):
        return []
    cache_machine_id = str(cache.get('machine_id') or '').strip().lower()
    if not cache_machine_id or cache_machine_id != _cache_machine_id():
        return []
    servers: list[tuple[str, str]] = []
    for row in rows:
        if isinstance(row, dict):
            host = str(row.get('host') or '').strip()
            port = str(row.get('port') or '').strip()
        else:
            parsed = _split_host_port(row)
            if not parsed:
                continue
            host, port = parsed
        if host and port.isdigit():
            servers.append((host, port))
            if len(servers) >= limit:
                break
    return servers


def _save_relay_cache_server(config: MonitorConfig, server: tuple[str, str] | None) -> None:
    if not server:
        return
    host, port = server
    if not host or not str(port).isdigit():
        return
    path = _relay_cache_path(config)
    existing = _load_relay_cache_servers(config, limit=8)
    ordered = [(host, str(port))]
    for item in existing:
        if item not in ordered:
            ordered.append(item)
        if len(ordered) >= 8:
            break
    payload = {
        'version': 1,
        'machine_id': _cache_machine_id(),
        'updated_at': datetime.now().isoformat(timespec='seconds'),
        'status_servers': [{'host': h, 'port': p} for h, p in ordered],
    }
    tmp_path = path.with_name(path.name + '.tmp')
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp_path.replace(path)


def _cached_status_servers(config: MonitorConfig, *, limit: int = 4) -> list[tuple[str, str]]:
    servers: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for server in _load_relay_cache_servers(config, limit=limit):
        if server not in seen:
            seen.add(server)
            servers.append(server)
            if len(servers) >= limit:
                return servers
    try:
        paths = sorted(config.paths.logs_dir.glob('monitor_live_*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        return []
    for path in paths[:40]:
        try:
            result = json.loads(path.read_text(encoding='utf-8-sig'))
        except Exception:
            continue
        if not isinstance(result, dict):
            continue
        server = _extract_status_server(result)
        if server and server not in seen:
            seen.add(server)
            servers.append(server)
            if len(servers) >= limit:
                break
    return servers


def _token_cache_path(config: MonitorConfig) -> Path:
    path = config.project_root / 'xmplayer' / 'config' / 'token_cache.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _cloud_cache_identity(config: MonitorConfig) -> str:
    try:
        login, password, _ = legacy_cli._resolve_cloud_login_password(
            explicit_login='', explicit_password='', login_file=str(config.cloud_login_file),
        )
        if not login or not password:
            return ''
        return credential_identity(login, password, legacy_cli.DEFAULT_ICSEE_APP_KEY,
                                   getattr(config, 'ams_base', '') or os.environ.get('XMPLAYER_AMS_BASE', ''))
    except (OSError, ValueError, RuntimeError):
        return ''


def _load_token_cache(config: MonitorConfig, *, serial_number: str, runtime_mode: str) -> tuple[str, str, dict[str, Any], dict[str, Any]] | None:
    path = _token_cache_path(config)
    if not path.exists():
        return None
    try:
        cache = json.loads(path.read_text(encoding='utf-8-sig'))
    except Exception:
        return None
    if not isinstance(cache, dict):
        return None
    identity = _cloud_cache_identity(config)
    if not identity or cache.get('account_identity') != identity:
        return None
    if str(cache.get('device_id') or '').strip() != serial_number:
        return None
    if str(cache.get('runtime_mode') or '').strip() != str(runtime_mode or '').strip():
        return None
    cache_machine_id = str(cache.get('machine_id') or '').strip().lower()
    if not cache_machine_id or cache_machine_id != _cache_machine_id():
        return None
    authcode = str(cache.get('authcode') or '').strip()
    admin_token = str(cache.get('admin_token') or '').strip()
    if not authcode or not admin_token:
        return None
    updated_at_epoch = float(cache.get('updated_at_epoch') or 0.0)
    age_seconds = max(0.0, time.time() - updated_at_epoch) if updated_at_epoch > 0 else TOKEN_CACHE_MAX_AGE_SECONDS + 1
    if age_seconds > TOKEN_CACHE_MAX_AGE_SECONDS:
        return None
    common = {
        'attempted': False,
        'source': 'token_cache',
        'cache_age_seconds': round(age_seconds, 1),
        'cache_path': str(path),
        'ams_base': str(cache.get('ams_base') or ''),
    }
    auth_info = dict(common)
    auth_info['mode'] = 'cached_authcode'
    admin_info = dict(common)
    admin_info['mode'] = 'cached_admin_token'
    return authcode, admin_token, auth_info, admin_info


def _save_token_cache(
    config: MonitorConfig,
    *,
    serial_number: str,
    runtime_mode: str,
    authcode: str,
    admin_token: str,
    ams_base: str = '',
) -> None:
    if not authcode or not admin_token:
        return
    path = _token_cache_path(config)
    payload = {
        'version': 2,
        'account_identity': _cloud_cache_identity(config),
        'ams_base': ams_base,
        'machine_id': _cache_machine_id(),
        'device_id': serial_number,
        'runtime_mode': runtime_mode,
        'updated_at': datetime.now().isoformat(timespec='seconds'),
        'updated_at_epoch': time.time(),
        'authcode': authcode,
        'admin_token': admin_token,
    }
    tmp_path = path.with_name(path.name + '.tmp')
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp_path.replace(path)


def _load_or_refresh_rps_tokens(
    config: MonitorConfig,
    *,
    raw_text: str,
    serial_number: str,
    refresh_timeout: int,
    runtime_mode: str,
    status_callback: StatusCallback | None,
    progress_callback: Callable[[str], None] | None = None,
    force_refresh: bool = False,
) -> tuple[str, dict[str, Any], str, dict[str, Any]]:
    if getattr(config, 'connection_mode', 'account') == 'cloud_id':
        from .cloud_id import CloudIdClient, CloudIdError
        _emit_progress(progress_callback, 'Cloud ID service codes request')
        _emit_status(status_callback, 'Connecting', 'Finding the camera by Cloud ID')
        client = CloudIdClient(timeout=min(refresh_timeout, 10), ssl_verify=False)
        try:
            codes = client.auth_codes(serial_number)
            status = client.discover_status(codes)
        except CloudIdError as exc:
            raise MonitorCaptureError(str(exc)) from None
        if status.status != 'Online':
            raise MonitorCaptureError('The camera is offline')
        host = str(status.entry.get('ServerIP') or '')
        port = str(status.entry.get('ServerPort') or '')
        if not host or not port.isdigit():
            raise MonitorCaptureError('The camera did not provide a connection address')
        _emit_progress(progress_callback, 'Cloud ID service codes response')
        return codes.for_service('rps'), {
            'source': 'cloud_id', 'mode': 'device_password',
            'status_server': [host, port],
        }, '', {'source': 'device_credentials', 'mode': 'password'}
    if not force_refresh:
        cached = _load_token_cache(config, serial_number=serial_number, runtime_mode=runtime_mode)
        if cached is not None:
            authcode, admin_token, auth_info, admin_info = cached
            _emit_progress(progress_callback, 'Cloud token cache response')
            _emit_status(status_callback, 'Connecting', 'Using cached cloud tokens')
            return authcode, auth_info, admin_token, admin_info

    _emit_progress(progress_callback, 'Cloud authcode request')
    _emit_status(status_callback, 'Connecting', 'Refreshing RPS authcode')
    authcode, authcode_refresh = legacy_cli._refresh_authcode_for_rps(
        text=raw_text,
        serial_number=serial_number,
        timeout=refresh_timeout,
        explicit_login='',
        explicit_password='',
        login_file=str(config.cloud_login_file),
        explicit_app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
        refresh_mode=runtime_mode,
        ssl_verify=False,
        explicit_ams_base=getattr(config, 'ams_base', ''),
    )
    if not authcode:
        raise MonitorCaptureError('failed to refresh authcode')
    _emit_progress(progress_callback, 'Cloud authcode response')

    _emit_progress(progress_callback, 'Cloud AdminToken request')
    _emit_status(status_callback, 'Connecting', 'Refreshing AdminToken')
    admin_token, admin_token_refresh = legacy_cli._refresh_admin_token_for_rps(
        text=raw_text,
        serial_number=serial_number,
        timeout=refresh_timeout,
        explicit_login='',
        explicit_password='',
        login_file=str(config.cloud_login_file),
        explicit_app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
        ssl_verify=False,
        explicit_ams_base=getattr(config, 'ams_base', ''),
    )
    if not admin_token:
        raise MonitorCaptureError('failed to refresh AdminToken')
    _emit_progress(progress_callback, 'Cloud AdminToken response')
    try:
        _save_token_cache(
            config,
            serial_number=serial_number,
            runtime_mode=runtime_mode,
            authcode=authcode,
            admin_token=admin_token,
            ams_base=str(authcode_refresh.get('ams_base') or ''),
        )
    except Exception:
        pass
    return authcode, authcode_refresh, admin_token, admin_token_refresh


def _detect_failure_stage(result: dict[str, Any]) -> dict[str, Any]:
    if result.get('status') == 'ok' or _result_has_second_video(result):
        return {}
    status_query = result.get('status_query') if isinstance(result.get('status_query'), dict) else {}
    pub_status = _summarize_pub_status(result)
    if not status_query or not status_query.get('ok'):
        return {
            'stage': 'pub_status_6510',
            'detail': _short_error(status_query.get('error') or pub_status.get('parsed_error') or 'pub-status did not return a usable response'),
        }
    if not pub_status.get('server'):
        return {
            'stage': 'pub_status_no_server',
            'detail': 'pub-status did not provide ServerIP/ServerPort',
        }

    agent_http = result.get('agent_http') if isinstance(result.get('agent_http'), dict) else {}
    selected = agent_http.get('selected') if isinstance(agent_http.get('selected'), dict) else {}
    parsed = selected.get('parsed') if isinstance(selected.get('parsed'), dict) else {}
    if not parsed.get('agent_server_ip') or not parsed.get('agent_server_port'):
        # Raw response_head can contain relay keys or echoed credentials.
        errors = _summarize_agent_protocol(result).get('errors') or []
        first_error = errors[0] if errors else ''
        return {
            'stage': 'agent_protocol_6510',
            'detail': first_error or 'AgentProtocol did not return a 6611 relay',
        }

    enc_probe = result.get('tcp_encrypted_probe') if isinstance(result.get('tcp_encrypted_probe'), dict) else {}
    if enc_probe.get('status') != 'ok':
        frames = enc_probe.get('frames') if isinstance(enc_probe.get('frames'), dict) else {}
        handshake = enc_probe.get('handshake') if isinstance(enc_probe.get('handshake'), dict) else {}
        detail = _short_error(enc_probe.get('error') or handshake.get('error') or frames.get('exit_reason')
                              or 'first 6611 control connection did not complete')
        return {
            'stage': 'first_6611',
            'detail': detail,
        }

    return {
        'stage': 'second_6611',
        'detail': 'second handoff did not produce video data',
    }


def describe_capture_failure(result: dict[str, Any]) -> str:
    failure = _detect_failure_stage(result)
    if not failure:
        return ''
    stage = str(failure.get('stage') or '').strip()
    detail = str(failure.get('detail') or '').strip()
    return f'{stage}: {detail}' if stage and detail else stage or detail


def summarize_live_probe_failure(result: dict[str, Any]) -> dict[str, Any]:
    """Small diagnostic summary for first/second 6611 failures."""
    enc_probe = result.get('tcp_encrypted_probe') if isinstance(result.get('tcp_encrypted_probe'), dict) else {}
    handshake = enc_probe.get('handshake') if isinstance(enc_probe.get('handshake'), dict) else {}
    claim = enc_probe.get('claim') if isinstance(enc_probe.get('claim'), dict) else {}
    frames = enc_probe.get('frames') if isinstance(enc_probe.get('frames'), dict) else {}
    controller = enc_probe.get('controller_summary') if isinstance(enc_probe.get('controller_summary'), dict) else {}
    bootstrap = enc_probe.get('local_bootstrap_summary') if isinstance(enc_probe.get('local_bootstrap_summary'), dict) else {}
    handoff_probe = (
        enc_probe.get('plain_handoff_probe')
        if isinstance(enc_probe.get('plain_handoff_probe'), dict)
        else result.get('tcp_plain_handoff_probe')
    )
    handoff_probe = handoff_probe if isinstance(handoff_probe, dict) else {}
    retry_rows: list[dict[str, Any]] = []
    agent_http = result.get('agent_http') if isinstance(result.get('agent_http'), dict) else {}
    for row in list(agent_http.get('rpscmd_retry_attempts') or [])[:16]:
        if not isinstance(row, dict) or not row.get('agent_server'):
            continue
        server_row = row.get('agent_server') if isinstance(row.get('agent_server'), dict) else {}
        row_frames = row.get('frames') if isinstance(row.get('frames'), dict) else {}
        retry_rows.append(
            {
                'i': row.get('selector_attempt_index'),
                'token': row.get('client_token_masked'),
                'server': (
                    f"{server_row.get('ip')}:{server_row.get('port')}"
                    if server_row.get('ip') and server_row.get('port')
                    else ''
                ),
                'status': row.get('probe_status'),
                'handshake': row.get('handshake_ok'),
                'control': row_frames.get('control'),
                'data': row_frames.get('data'),
            }
        )
    first_cmds: list[str] = []
    for item in list(frames.get('first_frames') or [])[:8]:
        if not isinstance(item, dict):
            continue
        cmd = item.get('cmd')
        msg_type = item.get('msg_type')
        try:
            cmd_text = f'0x{int(cmd):04x}'
        except Exception:
            cmd_text = str(cmd or '')
        first_cmds.append(f'{msg_type}:{cmd_text}' if msg_type not in (None, '') else cmd_text)
    return {
        'failure': describe_capture_failure(result),
        'agent_protocol': _summarize_agent_protocol(result),
        'agent_server': _summarize_agent_server(result),
        'encrypted_probe': {
            'stream_encoding': enc_probe.get('stream_encoding'),
            'endpoint': (
                f"{enc_probe.get('agent_host')}:{enc_probe.get('agent_port')}"
                if enc_probe.get('agent_host') and enc_probe.get('agent_port')
                else ''
            ),
            'status': enc_probe.get('status'),
            'error': _short_error(enc_probe.get('error') or claim.get('recv_error')),
            'handshake_ok': handshake.get('ok'),
            'handshake_error': _short_error(handshake.get('error')),
            'frames': _frame_counts(enc_probe),
            'cmd_counts': frames.get('cmd_counts') if isinstance(frames.get('cmd_counts'), dict) else {},
            'first_cmds': first_cmds,
            'controller_status': controller.get('status'),
            'bootstrap_status': bootstrap.get('status'),
        },
        'selector_retries': retry_rows,
        'second_6611': _summarize_handoff_probe(handoff_probe),
    }


def _iter_dicts(value: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(value, dict):
        out.append(value)
        for child in value.values():
            out.extend(_iter_dicts(child))
    elif isinstance(value, list):
        for child in value:
            out.extend(_iter_dicts(child))
    return out


def _pick_text(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ''):
            return str(value).strip()
    return ''


def _normalize_alarm_title(row: dict[str, Any]) -> str:
    raw = _pick_text(
        row,
        (
            'alarmName',
            'alarmTypeName',
            'eventName',
            'event',
            'alarmmsg',
            'title',
            'name',
            'typeName',
            'alarmType',
            'eventType',
            'msgType',
            'type',
        ),
    )
    lower = raw.lower()
    if any(item in lower for item in ('human', 'person', 'people', 'pedestrian', 'humanoid')):
        return 'Person detected'
    if any(item in lower for item in ('motion', 'move')):
        return 'Motion detected'
    if any(item in lower for item in ('alarm', 'event')):
        return 'Camera event'
    return raw or 'Camera message'


def _normalize_alarm_time(row: dict[str, Any]) -> str:
    raw = _pick_text(
        row,
        (
            'alarmTime',
            'eventTime',
            'createTime',
            'createDate',
            'time',
            'tm',
            'date',
            'startTime',
            'timestamp',
            'ut',
            'devut',
        ),
    )
    if not raw:
        return ''
    if raw.isdigit():
        value = int(raw)
        if value > 10_000_000_000:
            value = value // 1000
        try:
            return datetime.fromtimestamp(value).strftime('%m-%d %H:%M:%S')
        except Exception:
            return raw
    return raw


def _add_alarm_image_url(urls: list[str], value: Any) -> None:
    if value in (None, ''):
        return
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return
        if text.startswith(('http://', 'https://')):
            if text not in urls:
                urls.append(text)
            return
        for separator in ('|', ';', ','):
            if separator in text:
                for item in text.split(separator):
                    _add_alarm_image_url(urls, item)
                return
        return
    if isinstance(value, dict):
        for key in ('url', 'picurl', 'picUrl', 'thumbUrl', 'thumbnail', 'imageUrl', 'snapUrl'):
            if key in value:
                _add_alarm_image_url(urls, value.get(key))
        return
    if isinstance(value, list):
        for item in value:
            _add_alarm_image_url(urls, item)


def _normalize_alarm_images(row: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for key in (
        'picinfo',
        'picInfo',
        'piclist',
        'picList',
        'images',
        'imageList',
        'pictures',
        'snapshots',
    ):
        _add_alarm_image_url(urls, row.get(key))
    for key in (
        'image',
        'imageUrl',
        'imgUrl',
        'picUrl',
        'pictureUrl',
        'snapUrl',
        'thumbnail',
        'thumbUrl',
        'coverUrl',
    ):
        _add_alarm_image_url(urls, row.get(key))
    return urls


def _normalize_alarm_image(row: dict[str, Any]) -> str:
    urls = _normalize_alarm_images(row)
    return urls[0] if urls else ''


def _extract_alarm_rows(payload: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _iter_dicts(payload):
        keys = {str(key).lower() for key in item.keys()}
        looks_like_alarm = any(
            key in keys
            for key in (
                'alarmtime',
                'alarmtype',
                'eventtime',
                'eventtype',
                'createtime',
                'tm',
                'ut',
                'devut',
                'event',
                'alarmmsg',
                'picinfo',
                'imageurl',
                'picurl',
                'snapurl',
                'thumbnail',
            )
        )
        if not looks_like_alarm:
            continue
        marker = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)[:800]
        if marker in seen:
            continue
        seen.add(marker)
        rows.append(item)
    return rows


def _messages_from_results(results: list[legacy_api.HttpResult], *, limit: int) -> tuple[list[MonitorMessage], str]:
    target_limit = max(int(limit or 0), 0)
    messages: list[MonitorMessage] = []
    first_error = ''
    for result in results:
        if not first_error and result.error:
            first_error = str(result.error)
        if not result.ok and not (result.status is not None and 200 <= result.status < 300):
            continue
        rows = _extract_alarm_rows(result.json_data if result.json_data is not None else result.text)
        for row in rows:
            title = _normalize_alarm_title(row)
            timestamp = _normalize_alarm_time(row)
            detail = _pick_text(row, ('alarmmsg', 'message', 'msg', 'description', 'content', 'deviceName', 'devName'))
            image_urls = _normalize_alarm_images(row)
            image_url = image_urls[0] if image_urls else ''
            messages.append(MonitorMessage(title=title, timestamp=timestamp, detail=detail, image_url=image_url, image_urls=image_urls, raw=row))
            if target_limit > 0 and len(messages) >= target_limit:
                return messages, ''
    if messages:
        return messages, ''
    success_count = sum(1 for result in results if result.ok or (result.status is not None and 200 <= result.status < 300))
    if success_count > 0:
        return [], 'Alarm API responded, but no message rows were found'
    return [], first_error or 'Alarm API did not return a successful response'


def _alarm_row_marker(row: dict[str, Any]) -> str:
    for key in ('id', 'msgid', 'msgId', 'alarmId'):
        value = row.get(key)
        if value not in (None, ''):
            return f'{key}:{value}'
    return json.dumps(row, ensure_ascii=False, sort_keys=True, default=str)[:800]


def _append_alarm_messages(
    messages: list[MonitorMessage],
    payload: Any,
    *,
    limit: int,
    seen: set[str],
) -> int:
    added = 0
    target_limit = max(int(limit or 0), 0)
    for row in _extract_alarm_rows(payload):
        marker = _alarm_row_marker(row)
        if marker in seen:
            continue
        seen.add(marker)
        title = _normalize_alarm_title(row)
        timestamp = _normalize_alarm_time(row)
        detail = _pick_text(row, ('alarmmsg', 'message', 'msg', 'description', 'content', 'deviceName', 'devName'))
        image_urls = _normalize_alarm_images(row)
        image_url = image_urls[0] if image_urls else ''
        messages.append(MonitorMessage(title=title, timestamp=timestamp, detail=detail, image_url=image_url, image_urls=image_urls, raw=row))
        added += 1
        if target_limit > 0 and len(messages) >= target_limit:
            break
    return added


def _alarm_query_range(days: int = 7) -> tuple[str, str]:
    now = datetime.now()
    start = (now - timedelta(days=max(int(days) - 1, 0))).replace(hour=0, minute=0, second=0, microsecond=0)
    end = now.replace(hour=23, minute=59, second=59, microsecond=0)
    return start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')


def _extract_alarm_auth_context(
    extractor: legacy_api.CloudLiveExtractor,
    session: legacy_api.CloudAuthSession,
    *,
    device_id: str,
    timeout: int,
) -> tuple[str, str, str, dict[str, Any]]:
    session, devices, ams_attempts = extractor.fetch_ams_device_list(
        session=session,
        timeout=timeout,
        ssl_verify=False,
        serial_number=device_id,
    )
    matched = next((row for row in devices if str(row.get('_device_id') or '') == device_id), {})
    pms_auth = str(matched.get('pms') or '').strip()
    muserid = str(matched.get('deviceOwnerId') or matched.get('muserid') or matched.get('mUserId') or '').strip()

    acapp_attempts: list[legacy_api.HttpResult] = []
    if not pms_auth:
        session, acapp_rows, acapp_attempts = extractor.fetch_acapp_auth_list(
            session=session,
            serial_number=device_id,
            auth_type='pms',
            timeout=timeout,
            ssl_verify=False,
        )
        acapp_match = next((row for row in acapp_rows if str(row.get('_device_id') or '') == device_id), {})
        pms_auth = str(acapp_match.get('pms') or acapp_match.get('_auth_code') or '').strip()

    account_id = ''
    try:
        account_id = str(legacy_api._decode_jwt_payload(session.user_token).get('account') or '').strip()
    except Exception:
        account_id = ''

    meta = {
        'ams_attempts': len(ams_attempts),
        'ams_devices': len(devices),
        'has_alarm_auth': bool(pms_auth),
        'has_muserid': bool(muserid),
        'acapp_attempts': len(acapp_attempts),
    }
    return pms_auth, muserid, account_id, meta


def _alarm_service_hosts() -> list[str]:
    return [
        '45.255.134.177',
        'access-pms.secu100.net',
        '165.154.179.103',
    ]


def _call_alarm_service(
    *,
    host: str,
    payload: dict[str, Any],
    timeout: int,
    path: str = 'v2',
) -> legacy_api.HttpResult:
    safe_host = str(host or '').strip()
    safe_path = str(path or '').strip('/')
    url = f'https://{safe_host}:6502/{safe_path}' if safe_path else f'https://{safe_host}:6502/'
    return legacy_api.http_json(
        url=url,
        method='POST',
        payload=payload,
        headers={
            'Host': f'{safe_host}:6502',
            'Connection': 'close',
            'User-Agent': 'null-null-funsdk-v1.6.4f-Android',
        },
        timeout=timeout,
        ssl_verify=False,
    )


def _extract_storage_total(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    for key in ('count', 'total', 'totalCount'):
        value = payload.get(key)
        if value not in (None, ''):
            try:
                return int(value)
            except Exception:
                pass
    rows = payload.get('dt')
    if isinstance(rows, list):
        today = datetime.now().strftime('%Y-%m-%d')
        total = 0
        found = False
        for row in rows:
            if not isinstance(row, dict):
                continue
            nested = row.get('numlist')
            if isinstance(nested, list):
                for nested_row in nested:
                    if not isinstance(nested_row, dict):
                        continue
                    if str(nested_row.get('tm') or '') == today:
                        try:
                            return int(nested_row.get('count') or 0)
                        except Exception:
                            pass
                    value = nested_row.get('count')
                    if value in (None, ''):
                        continue
                    try:
                        total += int(value)
                        found = True
                    except Exception:
                        pass
                continue
            value = row.get('count')
            if value in (None, ''):
                continue
            try:
                total += int(value)
                found = True
            except Exception:
                pass
        if found:
            return total
    return None


def _fetch_alarm_storage_count(
    *,
    host: str,
    device_id: str,
    auth: str,
    muserid: str,
    account_id: str,
    start_time: str,
    end_time: str,
    timeout: int,
) -> tuple[int | None, legacy_api.HttpResult | None]:
    if not account_id:
        return None, None
    payload = {
        'msg': 'get_storage_count',
        'st': start_time,
        'et': end_time,
        'type': 'MSG',
        'userid': account_id,
        'snlist': [
            {
                'sn': device_id,
                'auth': auth,
                'muserid': muserid,
                'ch': 0,
                'fttp': 'or',
                'ltf': 'or',
            }
        ],
    }
    result = _call_alarm_service(host=host, payload=payload, timeout=timeout)
    data = result.json_data if isinstance(result.json_data, dict) else {}
    if str(data.get('code') or '') == '200':
        return _extract_storage_total(data), result
    return None, result


def discover_cloud_device_ids(config: MonitorConfig, *, timeout: int = 20) -> list[str]:
    if getattr(config, 'connection_mode', 'account') == 'cloud_id':
        _connection_login_text(config)
        return [config.device_id]
    login_issue = validate_cloud_login_file(config.cloud_login_file)
    if login_issue:
        raise MonitorCaptureError(login_issue)
    raw_text = config.cloud_login_file.read_text(encoding='utf-8-sig', errors='ignore')
    extractor, session, _login_attempts, _app_attempts, _login_context = legacy_cli._login_cloud_session_for_rps(
        text=raw_text,
        timeout=max(int(timeout), 12),
        explicit_login='',
        explicit_password='',
        login_file=str(config.cloud_login_file),
        explicit_app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
        ssl_verify=False,
        explicit_ams_base=getattr(config, 'ams_base', ''),
    )
    _session, devices, _attempts = extractor.fetch_ams_device_list(
        session=session,
        timeout=max(int(timeout), 12),
        ssl_verify=False,
    )
    device_ids: list[str] = []
    seen: set[str] = set()
    for device in devices:
        device_id = str(device.get('_device_id') or device.get('deviceId') or device.get('sn') or '').strip()
        if device_id and device_id not in seen:
            seen.add(device_id)
            device_ids.append(device_id)
    if not device_ids:
        raise MonitorCaptureError('No cameras were found for this app account')
    return device_ids


def fetch_monitor_messages(config: MonitorConfig, *, limit: int = 30, timeout: int = 12) -> tuple[list[MonitorMessage], dict[str, Any]]:
    if getattr(config, 'connection_mode', 'account') == 'cloud_id':
        raise MonitorCaptureError('Cloud messages require app account sign-in')
    login_issue = validate_cloud_login_file(config.cloud_login_file)
    if login_issue:
        raise MonitorCaptureError(login_issue)
    raw_text = config.cloud_login_file.read_text(encoding='utf-8-sig', errors='ignore') if config.cloud_login_file.exists() else ''
    extractor, session, login_attempts, app_attempts, login_context = legacy_cli._login_cloud_session_for_rps(
        text=raw_text,
        timeout=timeout,
        explicit_login='',
        explicit_password='',
        login_file=str(config.cloud_login_file),
        explicit_app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
        ssl_verify=False,
        explicit_ams_base=getattr(config, 'ams_base', ''),
        target_serial=config.device_id,
    )
    device_id = config.device_id.strip()
    auth, muserid, account_id, auth_meta = _extract_alarm_auth_context(
        extractor,
        session,
        device_id=device_id,
        timeout=timeout,
    )
    if not auth:
        raise MonitorCaptureError('failed to load PMS alarm auth from AMS device list')

    start_time, end_time = _alarm_query_range(days=7)
    requested_limit = max(int(limit or 0), 0)
    page_size = 100
    first_page_size = page_size if requested_limit <= 0 else min(max(requested_limit, 20), page_size)
    query_payload: dict[str, Any] = {
        'msg': 'alarm_query',
        'pgnum': 1,
        'pgsize': first_page_size,
        'sn': device_id,
        'auth': auth,
        'am': '1',
        'st': start_time,
        'et': end_time,
        'ch': 0,
        'fttp': 'or',
        'labelfttp': 'or',
        'labeldet': True,
    }
    if muserid:
        query_payload['muserid'] = muserid

    alarm_results: list[legacy_api.HttpResult] = []
    messages: list[MonitorMessage] = []
    seen_messages: set[str] = set()
    selected_host = ''
    warning = ''
    total_count = None
    storage_result = None
    for host in _alarm_service_hosts():
        result = _call_alarm_service(host=host, payload=query_payload, timeout=timeout)
        alarm_results.append(result)
        data = result.json_data if isinstance(result.json_data, dict) else {}
        if result.ok and str(data.get('code') or '') == '200':
            selected_host = host
            total_count, storage_result = _fetch_alarm_storage_count(
                host=selected_host,
                device_id=device_id,
                auth=auth,
                muserid=muserid,
                account_id=account_id,
                start_time=start_time,
                end_time=end_time,
                timeout=timeout,
            )
            target_limit = requested_limit
            if target_limit <= 0:
                target_limit = int(total_count or 0)
                if target_limit <= 0:
                    target_limit = page_size
            _append_alarm_messages(messages, data, limit=target_limit, seen=seen_messages)
            page = 2
            while len(messages) < target_limit:
                page_payload = dict(query_payload)
                page_payload['pgnum'] = page
                page_payload['pgsize'] = page_size
                page_result = _call_alarm_service(host=selected_host, payload=page_payload, timeout=timeout)
                alarm_results.append(page_result)
                page_data = page_result.json_data if isinstance(page_result.json_data, dict) else {}
                if not page_result.ok or str(page_data.get('code') or '') != '200':
                    if not warning:
                        warning = str(page_data.get('code') or page_result.error or 'alarm service page request failed')
                    break
                added = _append_alarm_messages(messages, page_data, limit=target_limit, seen=seen_messages)
                if added <= 0:
                    break
                page += 1
            break
        if not warning:
            warning = str(data.get('code') or result.error or 'alarm service request failed')

    if not messages:
        messages, parse_warning = _messages_from_results(alarm_results[-1:] if selected_host else alarm_results, limit=limit)
    else:
        parse_warning = ''
    if parse_warning:
        warning = parse_warning

    meta = {
        'login_attempts': len(login_attempts),
        'app_attempts': len(app_attempts),
        'auth_mode': str(login_context.get('login_mode') or ''),
        'alarm_path': 'pms_alarm_service',
        'alarm_host': selected_host,
        'alarm_requests': len(alarm_results),
        'alarm_count_status': storage_result.status if storage_result is not None else None,
        'total_count': total_count,
        'messages': len(messages),
        'warning': warning,
    }
    meta.update(auth_meta)
    return messages, meta


def _summarize_live_result(result: dict[str, Any]) -> dict[str, Any]:
    enc_probe = result.get('tcp_encrypted_probe') if isinstance(result.get('tcp_encrypted_probe'), dict) else {}
    claim = enc_probe.get('claim') if isinstance(enc_probe.get('claim'), dict) else {}
    handoff_probe = (
        enc_probe.get('plain_handoff_probe')
        if isinstance(enc_probe.get('plain_handoff_probe'), dict)
        else result.get('tcp_plain_handoff_probe')
    )
    attempts = result.get('attempts') if isinstance(result.get('attempts'), list) else []
    summary = {
        'log_mode': 'summary',
        'status': result.get('status'),
        'quality': result.get('quality'),
        'live_data_seen': bool(result.get('live_data_seen')),
        'selected_attempt_index': int(result.get('selected_attempt_index') or result.get('attempt_index') or 0),
        'attempt_count_total': int(result.get('attempt_count_total') or len(attempts) or 1),
        'controller_profile': result.get('controller_profile'),
        'runtime_mode': result.get('runtime_mode'),
        'pub_status': _summarize_pub_status(result),
        'agent_protocol': _summarize_agent_protocol(result),
        'agent_server': _summarize_agent_server(result),
        'failure': _detect_failure_stage(result),
        'encrypted_probe': {
            'status': enc_probe.get('status'),
            'frames': _frame_counts(enc_probe),
            'plain_handoff_start_reason': enc_probe.get('plain_handoff_start_reason'),
            'followups': _summarize_followups(claim.get('followups') or []),
        },
        'second_6611': _summarize_handoff_probe(handoff_probe if isinstance(handoff_probe, dict) else {}),
        'attempts': [
            {
                'index': int(item.get('attempt_index') or 0),
                'status': item.get('status'),
                'status_server_override': item.get('status_server_override'),
                'live_data_seen': bool(item.get('live_data_seen')),
                'second_video': _result_has_second_video(item),
            }
            for item in attempts
        ],
    }
    if result.get('status_server_override'):
        summary['status_server_override'] = result.get('status_server_override')
    return summary


def _connection_login_text(config: MonitorConfig) -> str:
    issue = validate_connection_credentials(config)
    if issue:
        raise MonitorCaptureError(issue)
    if getattr(config, 'connection_mode', 'account') == 'cloud_id':
        return ''
    return config.cloud_login_file.read_text(encoding='utf-8-sig', errors='ignore')


def _make_rps_chain(config: MonitorConfig, auth_info: dict[str, Any]) -> legacy_api.RpsLiveChain:
    server = auth_info.get('status_server') if getattr(config, 'connection_mode', 'account') == 'cloud_id' else None
    return legacy_api.RpsLiveChain(
        status_base=legacy_api.DEFAULT_STATUS_BASE,
        status_user_agent=legacy_api.DEFAULT_STATUS_UA,
        status_content_type='text/html', status_ssl_verify=False, agent_ssl_verify=False,
        preferred_status_server=tuple(server) if server else None,
    )


def _check_device_login(config: MonitorConfig, result: dict[str, Any]) -> None:
    if getattr(config, 'connection_mode', 'account') != 'cloud_id':
        return
    frames = ((result.get('tcp_encrypted_probe') or {}).get('frames') or {}).get('control_frames') or []
    for frame in frames:
        if frame.get('cmd') != 0x03E9:
            continue
        ret = _control_frame_json(frame).get('Ret')
        if ret in {203, 204, 205, 206, 214, 215}:
            detail = ('The camera user is locked. Try again later.' if ret == 205 else
                      'The camera rejected sign-in. Check its username and password.')
            raise MonitorCaptureError(f'{detail} (code {ret})')


def _build_login_followup(serial_number: str, admin_token: str, controller_profile: str,
                          *, config: MonitorConfig | None = None) -> dict[str, Any]:
    if config is not None and getattr(config, 'connection_mode', 'account') == 'cloud_id':
        return {
            'username': config.device_username, 'password': config.device_password,
            'mode': 'password', 'login_type': 'DVRIP-Web',
            'random_a': legacy_api._generate_ascii_key(32),
            'user_agent': legacy_cli.DEFAULT_6611_LOGIN_USER_AGENT,
            **({'msg_id': 0x38} if controller_profile == 'app_reference_first_6611' else {}),
        }
    token_username = legacy_api.derive_futurehome_token_username(serial_number, admin_token) if admin_token else ''
    followup = {
        'username': '',
        'password': '',
        'admin_token': admin_token,
        'login_type': legacy_cli.DEFAULT_6611_LOGIN_TYPE,
        'token_username': token_username,
        'user_agent': legacy_cli.DEFAULT_6611_LOGIN_USER_AGENT,
        'communicate_key': '',
        'transport_key': '',
        'mode': 'auto',
    }
    if controller_profile == 'app_reference_first_6611':
        followup['msg_id'] = 0x38
    return followup


def _parse_recording_time(value: Any) -> datetime | None:
    text = str(value or '').strip()
    if not text:
        return None
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S'):
        try:
            return datetime.strptime(text, fmt)
        except Exception:
            pass
    return None


def _parse_intish(value: Any) -> int:
    if value in (None, ''):
        return 0
    text = str(value).strip()
    try:
        return int(text, 0)
    except Exception:
        try:
            return int(float(text))
        except Exception:
            return 0


def _recording_title(row: dict[str, Any]) -> str:
    file_name = str(row.get('FileName') or '').strip()
    begin_time = str(row.get('BeginTime') or '').strip()
    time_label = begin_time.split(' ', 1)[1] if ' ' in begin_time else begin_time
    lower_name = file_name.lower()
    if '[m]' in lower_name:
        prefix = 'Motion'
    elif '[r]' in lower_name:
        prefix = 'Continuous recording'
    else:
        prefix = 'Recording'
    return f'{prefix} {time_label}'.strip()


def _recordings_from_opfilequery(payload: dict[str, Any]) -> list[RecordingItem]:
    rows = payload.get('OPFileQuery')
    if not isinstance(rows, list):
        return []
    recordings: list[RecordingItem] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        begin_time = str(row.get('BeginTime') or '').strip()
        end_time = str(row.get('EndTime') or '').strip()
        start_dt = _parse_recording_time(begin_time)
        end_dt = _parse_recording_time(end_time)
        duration = 0
        if start_dt is not None and end_dt is not None:
            duration = max(int((end_dt - start_dt).total_seconds()), 0)
        recordings.append(
            RecordingItem(
                title=_recording_title(row),
                start_time=begin_time,
                end_time=end_time,
                duration_seconds=duration,
                file_name=str(row.get('FileName') or '').strip(),
                file_length=_parse_intish(row.get('FileLength')),
                channel=_parse_intish(row.get('Channel')),
                raw=row,
            )
        )
    recordings.sort(key=lambda item: item.start_time, reverse=True)
    return recordings


def _control_frame_json(frame: dict[str, Any]) -> dict[str, Any]:
    for key in ('dataenc_decrypted_json', 'aes_decrypted_json', 'dataenc_json', 'aes_json'):
        value = frame.get(key)
        if isinstance(value, dict):
            return value
    for key in ('dataenc_decrypted_text', 'aes_decrypted_text', 'payload_text'):
        value = frame.get(key)
        if not isinstance(value, str) or not value.strip().startswith('{'):
            continue
        try:
            parsed = json.loads(value.strip())
        except Exception:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def _find_opfilequery_response(result: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    enc_probe = result.get('tcp_encrypted_probe') if isinstance(result.get('tcp_encrypted_probe'), dict) else result
    frames = (enc_probe.get('frames') or {}) if isinstance(enc_probe, dict) else {}
    meta = {
        'status': result.get('status'),
        'encrypted_status': enc_probe.get('status') if isinstance(enc_probe, dict) else '',
        'cmd_counts': frames.get('cmd_counts') if isinstance(frames, dict) else {},
        'exit_reason': frames.get('exit_reason') if isinstance(frames, dict) else '',
        'duration_seconds': frames.get('duration_seconds') if isinstance(frames, dict) else None,
    }
    claim = enc_probe.get('claim') if isinstance(enc_probe.get('claim'), dict) else {}
    if claim.get('recv_error'):
        meta['recv_error'] = claim.get('recv_error')
    if claim.get('followup_send_error'):
        meta['followup_send_error'] = claim.get('followup_send_error')
    control_frames = frames.get('control_frames') if isinstance(frames, dict) else []
    if not isinstance(control_frames, list):
        return None, meta
    frame_notes: list[dict[str, Any]] = []
    for frame in control_frames:
        if not isinstance(frame, dict):
            continue
        cmd = _parse_intish(frame.get('cmd'))
        data = _control_frame_json(frame)
        if len(frame_notes) < 8:
            note = {
                'cmd': f'0x{cmd:04x}',
                'ret': data.get('Ret') if data else None,
                'name': data.get('Name') if data else '',
            }
            frame_notes.append(note)
        if cmd != 0x05A1 and not (isinstance(data, dict) and ('OPFileQuery' in data or data.get('Name') == 'OPFileQuery')):
            continue
        if data:
            meta['response_cmd'] = f'0x{cmd:04x}'
            meta['response_ret'] = data.get('Ret')
            meta['response_session_id'] = data.get('SessionID')
            return data, meta
        meta['response_error'] = frame.get('dataenc_decrypt_error') or 'OPFileQuery response was not decrypted'
        return None, meta
    if frame_notes:
        meta['control_frame_notes'] = frame_notes
    return None, meta


def _build_opfilequery_followup(begin_time: str, end_time: str) -> dict[str, Any]:
    payload_text = json.dumps(
        {
            'Name': 'OPFileQuery',
            'OPFileQuery': {
                'BeginTime': begin_time,
                'EndTime': end_time,
                'Channel': 0,
                'DriverTypeMask': '0x0000FFFF',
                'StreamType': '0x00000000',
                'Event': '*',
                'Type': 'h264',
            },
        },
        ensure_ascii=False,
        separators=(',', ':'),
    )
    return {
        'send_phase': 'post_login',
        'msg_type': 0,
        'session_id': 0,
        'msg_id': 0x48,
        'unk': 0,
        'cmd': 0x05A0,
        'code': 0,
        'code_endian': 'be',
        'plain_payload_text': payload_text,
        'delay_before': 0.2,
        'stop_after_response_cmd': 0x05A1,
    }


def _recording_key(item: RecordingItem) -> tuple[str, str, str, int]:
    return (item.file_name.lower(), item.start_time, item.end_time, item.channel)


def _recording_progress_time(item: RecordingItem) -> datetime | None:
    end_dt = _parse_recording_time(item.end_time)
    if end_dt is not None:
        return end_dt
    start_dt = _parse_recording_time(item.start_time)
    if start_dt is None:
        return None
    return start_dt + timedelta(seconds=max(int(item.duration_seconds or 0), 1))


def _recording_server_attempts(
    cached_servers: list[tuple[str, str]],
    preferred_server: tuple[str, str] | None,
) -> list[tuple[str, str]]:
    attempts: list[tuple[str, str]] = []
    if preferred_server:
        attempts.append(preferred_server)
    for server in cached_servers:
        if server not in attempts:
            attempts.append(server)
    if ('', '') not in attempts:
        attempts.append(('', ''))
    return attempts


def _query_device_recordings_page(
    *,
    config: MonitorConfig,
    chain: legacy_api.RpsLiveChain,
    serial_number: str,
    authcode: str,
    admin_token: str,
    controller_profile: str,
    begin_time: str,
    end_time: str,
    timeout: int,
    server_attempts: list[tuple[str, str]],
    stop_event: threading.Event | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any], tuple[str, str] | None]:
    followup = _build_opfilequery_followup(begin_time, end_time)
    last_meta: dict[str, Any] = {'begin_time': begin_time, 'end_time': end_time}
    for status_host, status_port in server_attempts:
        _raise_if_cancelled(stop_event)
        result = chain.run(
            serial_number=serial_number,
            authcode=authcode,
            status_server_ip=status_host,
            status_server_port=status_port,
            client_token=_agent_client_token(config),
            session_id=legacy_api.build_session_id(),
            dest_port='34567',
            service_type='RpsCmd',
            encrypt='1',
            step='0',
            protocol_mode='tcp',
            vendor='',
            developer_id='',
            app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
            timeout=max(int(timeout), 12),
            channel=0,
            stream_type='Main',
            trans_mode='TCP',
            combine_mode='NONE',
            msg_id=0x18,
            code=0x00008505,
            code_endian='be',
            capture_seconds=12.0,
            max_frames=512,
            tcp_mode='encrypted',
            encrypted_session_int=0x1869F,
            encrypted_msg_id=0x30 if controller_profile == 'app_reference_first_6611' else 0x10,
            encrypted_unk=0x63,
            encrypted_cmd=0x0585,
            encrypted_claim_random_a='',
            encrypted_session_hex_width=10,
            encrypted_stream_type='Extra1',
            encrypted_combine_mode='CONNECT_ALL',
            encrypted_trans_mode='TCP',
            encrypted_followup_frames=[followup],
            encrypted_followup_delay=0.0,
            encrypted_login_followup=_build_login_followup(serial_number, admin_token, controller_profile, config=config),
            encrypted_controller_auto=False,
            encrypted_controller_profile=controller_profile,
            plain_handoff=False,
            runtime_mode=config.runtime_mode,
            stop_event=stop_event,
        )
        _check_device_login(config, result)
        response, page_meta = _find_opfilequery_response(result)
        page_meta.update({'begin_time': begin_time, 'end_time': end_time})
        failure_detail = describe_capture_failure(result)
        if failure_detail:
            page_meta['failure'] = failure_detail
        if status_host and status_port:
            page_meta['status_server_override'] = f'{status_host}:{status_port}'
        last_meta = page_meta
        if isinstance(response, dict):
            return response, page_meta, _extract_status_server(result)
    return None, last_meta, None


def fetch_device_recordings(
    config: MonitorConfig,
    *,
    day: datetime | None = None,
    timeout: int = 20,
    max_pages: int = 8,
    stop_event: threading.Event | None = None,
) -> tuple[list[RecordingItem], dict[str, Any]]:
    _raise_if_cancelled(stop_event)
    raw_text = _connection_login_text(config)
    serial_number = config.device_id.strip()
    if not serial_number:
        raise MonitorCaptureError('device_id is empty')

    query_day = day or datetime.now()
    day_begin_dt = query_day.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end_dt = query_day.replace(hour=23, minute=59, second=59, microsecond=0)
    end_time = day_end_dt.strftime('%Y-%m-%d %H:%M:%S')
    authcode, authcode_refresh, admin_token, admin_token_refresh = _load_or_refresh_rps_tokens(
        config,
        raw_text=raw_text,
        serial_number=serial_number,
        refresh_timeout=max(int(timeout), 12),
        runtime_mode=config.runtime_mode,
        status_callback=None,
    )
    chain = _make_rps_chain(config, authcode_refresh)
    controller_profile = config.controller_profile
    cached_servers = _cached_status_servers(config, limit=2)
    preferred_server: tuple[str, str] | None = None
    recordings_by_key: dict[tuple[str, str, str, int], RecordingItem] = {}
    pages: list[dict[str, Any]] = []
    page_begin_dt = day_begin_dt
    last_meta: dict[str, Any] = {}
    last_success_ret: Any = None
    partial_error = ''

    for page_index in range(max(int(max_pages), 1)):
        _raise_if_cancelled(stop_event)
        if page_begin_dt > day_end_dt:
            break
        begin_time = page_begin_dt.strftime('%Y-%m-%d %H:%M:%S')
        response, page_meta, good_server = _query_device_recordings_page(
            config=config,
            chain=chain,
            serial_number=serial_number,
            authcode=authcode,
            admin_token=admin_token,
            controller_profile=controller_profile,
            begin_time=begin_time,
            end_time=end_time,
            timeout=timeout,
            server_attempts=_recording_server_attempts(cached_servers, preferred_server),
            stop_event=stop_event,
        )
        last_meta = page_meta
        page_summary: dict[str, Any] = {
            'page': page_index + 1,
            'begin_time': begin_time,
            'end_time': end_time,
            'status_server_override': page_meta.get('status_server_override', ''),
        }
        if good_server:
            preferred_server = good_server
            try:
                _save_relay_cache_server(config, good_server)
            except Exception:
                pass
        if not isinstance(response, dict):
            page_summary['error'] = page_meta.get('response_error') or page_meta.get('failure') or 'OPFileQuery response not found'
            pages.append(page_summary)
            if recordings_by_key:
                break
            prefix = 'OPFileQuery response not found'
            if page_meta.get('failure') and not page_meta.get('response_error') and not page_meta.get('cmd_counts'):
                prefix = 'recordings relay setup failed'
            raise MonitorCaptureError(f"{prefix}: {page_summary['error']} cmd_counts={page_meta.get('cmd_counts')}")
        ret = _parse_intish(response.get('Ret'))
        if ret not in (0, 100):
            page_summary['ret'] = response.get('Ret')
            page_summary['error'] = f'OPFileQuery failed: Ret={response.get("Ret")}'
            pages.append(page_summary)
            if recordings_by_key:
                partial_error = str(page_summary['error'])
                break
            raise MonitorCaptureError(f'OPFileQuery failed: Ret={ret}')
        last_success_ret = response.get('Ret')

        page_recordings = _recordings_from_opfilequery(response)
        new_count = 0
        for item in page_recordings:
            key = _recording_key(item)
            if key in recordings_by_key:
                continue
            recordings_by_key[key] = item
            new_count += 1
        page_summary.update(
            {
                'ret': response.get('Ret'),
                'count': len(page_recordings),
                'new_count': new_count,
            }
        )
        pages.append(page_summary)
        if not page_recordings:
            break
        if len(page_recordings) < OPFILEQUERY_PAGE_CAP_HINT:
            break

        progress_times = [value for value in (_recording_progress_time(item) for item in page_recordings) if value is not None]
        if not progress_times:
            break
        next_begin_dt = max(progress_times) + timedelta(seconds=1)
        if next_begin_dt <= page_begin_dt:
            break
        page_begin_dt = next_begin_dt
        if new_count == 0:
            break

    recordings = list(recordings_by_key.values())
    recordings.sort(key=lambda item: item.start_time, reverse=True)
    meta: dict[str, Any] = {}
    meta.update(
        {
            'begin_time': day_begin_dt.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time,
            'authcode_source': authcode_refresh.get('source') if isinstance(authcode_refresh, dict) else '',
            'admin_token_source': admin_token_refresh.get('source') if isinstance(admin_token_refresh, dict) else '',
            'response_ret': last_success_ret,
            'partial_error': partial_error,
            'pages': pages,
            'page_count': len(pages),
            'total_count': len(recordings),
        }
    )
    if last_meta:
        meta['last_cmd_counts'] = last_meta.get('cmd_counts')
    return recordings, meta



def _recording_end_time(item: RecordingItem) -> str:
    if item.end_time:
        return item.end_time
    start_dt = _parse_recording_time(item.start_time)
    if start_dt is None:
        return item.start_time
    seconds = max(int(item.duration_seconds or 0), 1)
    return (start_dt + timedelta(seconds=seconds)).strftime('%Y-%m-%d %H:%M:%S')


def _recording_day_end_time(item: RecordingItem) -> str:
    start_dt = _parse_recording_time(item.start_time)
    if start_dt is None:
        return _recording_end_time(item)
    return start_dt.replace(hour=23, minute=59, second=59).strftime('%Y-%m-%d %H:%M:%S')


def _build_opplayback_payload(
    item: RecordingItem,
    *,
    action: str,
    session_id: str = '{{SESSION_ID}}',
    end_time_mode: str = 'day_end',
    vekey1: str = '',
) -> str:
    end_time = _recording_day_end_time(item) if end_time_mode == 'day_end' else _recording_end_time(item)
    parameter: dict[str, Any] = {
        'PlayMode': 'ByTime',
        # The Android app passes a placeholder filename for ByTime playback.
        'FileName': PLAYBACK_BY_TIME_DUMMY_FILE,
        'Channel': int(item.channel or 0),
        'StreamType': 0,
        'Value': 0,
        'TransMode': 'TCP',
        'IntelligentPlayBackEvent': 'ALL',
        'IntelligentPlayBackSpeed': 0,
    }
    if action == 'Start' and vekey1:
        parameter['VEKEY1'] = vekey1
    payload = {
        'Name': 'OPPlayBack',
        'OPPlayBack': {
            'Action': action,
            'Parameter': parameter,
            'StartTime': item.start_time,
            'EndTime': end_time,
        },
        'SessionID': session_id,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(',', ':'))


def _build_opplayback_followup(
    item: RecordingItem,
    *,
    action: str,
    cmd: int,
    msg_id: int,
    send_phase: str,
    delay_before: float = 0.0,
    wait_for_response_cmd: int = 0,
    wait_for_response_ret: int | None = None,
    vekey1: str = '',
    end_time_mode: str = 'day_end',
) -> dict[str, Any]:
    payload_text = _build_opplayback_payload(item, action=action, vekey1=vekey1, end_time_mode=end_time_mode)
    followup: dict[str, Any] = {
        'send_phase': send_phase,
        'msg_type': 0,
        'session_id': 0,
        'msg_id': int(msg_id),
        'unk': 0,
        'cmd': int(cmd),
        'code': 0,
        'code_endian': 'be',
        'plain_payload_text': payload_text,
        'dataenc': False,
        'delay_before': float(delay_before),
    }
    if wait_for_response_cmd:
        followup['wait_for_response_cmd'] = int(wait_for_response_cmd)
    if wait_for_response_ret is not None:
        followup['wait_for_response_ret'] = int(wait_for_response_ret)
    return followup


def run_recording_playback_stream(
    config: MonitorConfig,
    recording: RecordingItem,
    *,
    stop_event: threading.Event | None = None,
    status_callback: StatusCallback | None = None,
    data_frame_callback: Callable[[bytes, str], bool | None] | None = None,
    attempts: int | None = None,
    capture_seconds: float | None = None,
) -> CaptureArtifacts:
    _raise_if_cancelled(stop_event)
    raw_text = _connection_login_text(config)
    serial_number = config.device_id.strip()
    if not serial_number:
        raise MonitorCaptureError('device_id is empty')
    if not recording.start_time:
        raise MonitorCaptureError('recording start_time is empty')

    timeout = 20
    refresh_timeout = max(timeout, 12)
    runtime_mode = config.runtime_mode
    controller_profile = config.controller_profile
    attempt_count = attempts if attempts is not None else max(1, min(config.attempts, 2))
    duration = max(int(recording.duration_seconds or 0), 0)
    stream_seconds = float(capture_seconds) if capture_seconds is not None else max(float(config.capture_seconds), float(duration + 8 if duration else 45))
    stream_seconds = max(12.0, min(stream_seconds, 600.0) if capture_seconds is None else stream_seconds)
    max_frames = max(int(config.max_frames), 65536, int(stream_seconds * 300) if capture_seconds is not None else 0)
    progress = _StartupProgress(status_callback, total_steps=34)

    authcode, authcode_refresh, admin_token, admin_token_refresh = _load_or_refresh_rps_tokens(
        config,
        raw_text=raw_text,
        serial_number=serial_number,
        refresh_timeout=refresh_timeout,
        runtime_mode=runtime_mode,
        status_callback=status_callback,
        progress_callback=progress.emit,
    )

    chain = _make_rps_chain(config, authcode_refresh)
    encrypted_login_followup = _build_login_followup(serial_number, admin_token, controller_profile, config=config)
    base_client_token = _agent_client_token(config)
    playback_followups = [
        _build_opplayback_followup(
            recording,
            action='Claim',
            cmd=0x0590,
            msg_id=0x50,
            send_phase='post_login_playback_claim',
            delay_before=0.0,
            end_time_mode=PLAYBACK_END_TIME_MODE,
        ),
        _build_opplayback_followup(
            recording,
            action='SetIntelligentType',
            cmd=0x058C,
            msg_id=0x58,
            send_phase='post_claim_playback_set_intelligent_type',
            delay_before=0.05,
            wait_for_response_cmd=0x0591,
            wait_for_response_ret=100,
            end_time_mode=PLAYBACK_END_TIME_MODE,
        ),
        _build_opplayback_followup(
            recording,
            action='Start',
            cmd=0x058C,
            msg_id=0x60,
            send_phase='post_claim_playback_start',
            delay_before=0.15,
            vekey1='{{VEKEY1}}',
            end_time_mode=PLAYBACK_END_TIME_MODE,
        ),
    ]

    best_result: dict[str, Any] | None = None
    all_results: list[dict[str, Any]] = []
    playback_data_seen = False
    cached_servers = _cached_status_servers(config)

    def _wrapped_data_callback(payload: bytes, vekey1: str) -> None:
        nonlocal playback_data_seen
        if stop_event is not None and stop_event.is_set():
            return
        meaningful_media = False
        if data_frame_callback is not None:
            meaningful_media = bool(data_frame_callback(payload, vekey1))
        if not meaningful_media:
            return
        if not playback_data_seen:
            playback_data_seen = True
            progress.set_state('Buffering')
            progress.emit('Recording media response first video packet')
            _emit_status(status_callback, 'Live', 'Receiving recording video')

    for attempt_index in range(1, attempt_count + 1):
        _raise_if_cancelled(stop_event)
        state = 'Connecting' if attempt_index == 1 else 'Retrying'
        progress.set_state(state)
        status_server_override: tuple[str, str] | None = None
        previous_failure = _detect_failure_stage(best_result).get('stage') if isinstance(best_result, dict) else ''
        if previous_failure in {'pub_status_6510', 'pub_status_no_server'} and cached_servers:
            status_server_override = cached_servers[min(attempt_index - 2, len(cached_servers) - 1)]
        progress.emit(f'Recording playback attempt {attempt_index}/{attempt_count} request')
        _emit_status(status_callback, state, f'Recording playback attempt {attempt_index}/{attempt_count}')
        result = chain.run(
            serial_number=serial_number,
            authcode=authcode,
            status_server_ip=status_server_override[0] if status_server_override else '',
            status_server_port=status_server_override[1] if status_server_override else '',
            client_token=base_client_token,
            session_id=legacy_api.build_session_id(),
            dest_port='34567',
            service_type='RpsCmd',
            encrypt='1',
            step='0',
            protocol_mode='tcp',
            vendor='',
            developer_id='',
            app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
            timeout=timeout,
            channel=int(recording.channel or 0),
            stream_type='Main',
            trans_mode='TCP',
            combine_mode='NONE',
            msg_id=0x18,
            code=0x00008505,
            code_endian='be',
            capture_seconds=stream_seconds,
            max_frames=max_frames,
            tcp_mode='encrypted',
            encrypted_session_int=0x1869F,
            encrypted_msg_id=0x30 if controller_profile == 'app_reference_first_6611' else 0x10,
            encrypted_unk=0x63,
            encrypted_cmd=0x0585,
            encrypted_claim_random_a='',
            encrypted_session_hex_width=10,
            encrypted_stream_type='Main',
            encrypted_combine_mode='CONNECT_ALL',
            encrypted_trans_mode='TCP',
            encrypted_followup_frames=playback_followups,
            encrypted_followup_delay=0.0,
            encrypted_login_followup=encrypted_login_followup,
            encrypted_controller_auto=False,
            encrypted_controller_profile=controller_profile,
            plain_handoff=False,
            plain_handoff_trigger='after_playback_claim_591',
            plain_handoff_stream_type='Main',
            plain_handoff_initial_payload_text='',
            plain_handoff_initial_code=0x00008C05,
            plain_handoff_claim_replay_count=0,
            gwm_ams_url='',
            device_oem_id='',
            device_hardware='',
            device_idr_auto_wakeup=False,
            wakeup_probe_enabled=True,
            wakeup_host='',
            wakeup_port=0,
            runtime_mode=runtime_mode,
            stop_event=stop_event,
            plain_handoff_data_frame_callback=_wrapped_data_callback,
            plain_handoff_extend_on_activity=True,
            progress_callback=progress.emit,
        )
        _check_device_login(config, result)
        progress.emit(f'Recording playback attempt {attempt_index}/{attempt_count} response {result.get("status") or "unknown"}')
        if status_server_override:
            result['status_server_override'] = f'{status_server_override[0]}:{status_server_override[1]}'
        result['attempt_index'] = attempt_index
        result['recording'] = {
            'title': recording.title,
            'start_time': recording.start_time,
            'end_time': recording.end_time,
            'file_name': recording.file_name,
            'duration_seconds': recording.duration_seconds,
        }
        result['authcode_refresh'] = authcode_refresh
        result['admin_token_refresh'] = admin_token_refresh
        result['controller_profile'] = controller_profile
        result['runtime_mode'] = runtime_mode
        result['playback_data_seen'] = playback_data_seen
        all_results.append(result)
        if best_result is None or _score_result(result) > _score_result(best_result):
            best_result = result
        if playback_data_seen or _result_has_second_video(result):
            break

    if best_result is None:
        raise MonitorCaptureError('no recording playback result produced')
    selected_attempt_index = int(best_result.get('attempt_index') or 0)
    best_result = dict(best_result)
    best_result['attempts'] = [dict(item) for item in all_results]
    best_result['selected_attempt_index'] = selected_attempt_index
    best_result['attempt_count_total'] = attempt_count
    try:
        _save_relay_cache_server(config, _extract_status_server(best_result))
    except Exception:
        pass

    return CaptureArtifacts(
        run_json_path=_disabled_log_path(config, 'recording_playback', 'recording'),
        result=best_result,
        quality='recording',
        attempt_count=attempt_count,
    )



def run_monitor_capture(
    config: MonitorConfig,
    *,
    quality: str,
    stop_event: threading.Event | None = None,
    status_callback: StatusCallback | None = None,
    attempts: int | None = None,
    timeout: int | None = None,
    capture_seconds: float | None = None,
    max_frames: int | None = None,
    progress_callback: Callable[[str], None] | None = None,
    include_agent_response_metadata: bool = False,
) -> CaptureArtifacts:
    _raise_if_cancelled(stop_event)
    raw_text = _connection_login_text(config)
    serial_number = config.device_id.strip()
    if not serial_number:
        raise MonitorCaptureError('device_id is empty')

    effective_timeout = max(int(timeout or 20), 3)
    refresh_timeout = max(effective_timeout, 12)
    runtime_mode = config.runtime_mode
    controller_profile = config.controller_profile
    controller_stream_type = 'Main'
    handoff_stream_type = _quality_to_handoff_stream_type(quality)
    default_attempt_count = config.attempts if runtime_mode == legacy_cli.RPS_CHAIN_RUNTIME_EXPERIMENTAL else 1
    attempt_count = attempts if attempts is not None else default_attempt_count
    effective_capture_seconds = max(float(capture_seconds if capture_seconds is not None else config.capture_seconds), 1.0)
    effective_max_frames = max(int(max_frames if max_frames is not None else config.max_frames), 8)

    authcode, authcode_refresh, admin_token, admin_token_refresh = _load_or_refresh_rps_tokens(
        config,
        raw_text=raw_text,
        serial_number=serial_number,
        refresh_timeout=refresh_timeout,
        runtime_mode=runtime_mode,
        status_callback=status_callback,
        progress_callback=progress_callback,
    )

    _raise_if_cancelled(stop_event)
    chain = _make_rps_chain(config, authcode_refresh)
    encrypted_login_followup = _build_login_followup(serial_number, admin_token, controller_profile, config=config)
    base_client_token = _agent_client_token(config)
    best_result: dict[str, Any] | None = None
    all_results: list[dict[str, Any]] = []

    for attempt_index in range(1, attempt_count + 1):
        _raise_if_cancelled(stop_event)
        state = 'Connecting' if attempt_index == 1 else 'Retrying'
        _emit_status(status_callback, state, f'Live attempt {attempt_index}/{attempt_count}')
        _emit_progress(progress_callback, f'Live attempt {attempt_index}/{attempt_count} request')
        session_id = legacy_api.build_session_id()
        result = chain.run(
            serial_number=serial_number,
            authcode=authcode,
            status_server_ip='',
            status_server_port='',
            client_token=base_client_token,
            session_id=session_id,
            dest_port='34567',
            service_type='RpsCmd',
            encrypt='1',
            step='0',
            protocol_mode='tcp',
            vendor='',
            developer_id='',
            app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
            timeout=effective_timeout,
            channel=0,
            stream_type=controller_stream_type,
            trans_mode='TCP',
            combine_mode='NONE',
            msg_id=0x18,
            code=0x00008505,
            code_endian='be',
            capture_seconds=effective_capture_seconds,
            max_frames=effective_max_frames,
            tcp_mode='encrypted',
            encrypted_session_int=0x1869F,
            encrypted_msg_id=0x30 if controller_profile == 'app_reference_first_6611' else 0x10,
            encrypted_unk=0x63,
            encrypted_cmd=0x0585,
            encrypted_claim_random_a='',
            encrypted_session_hex_width=10,
            encrypted_stream_type=handoff_stream_type,
            encrypted_combine_mode='CONNECT_ALL',
            encrypted_trans_mode='TCP',
            encrypted_followup_frames=[],
            encrypted_followup_delay=0.0,
            encrypted_login_followup=encrypted_login_followup,
            encrypted_controller_auto=True,
            encrypted_controller_profile=controller_profile,
            plain_handoff=True,
            plain_handoff_trigger='after_second_413',
            plain_handoff_stream_type=handoff_stream_type,
            gwm_ams_url='',
            device_oem_id='',
            device_hardware='',
            device_idr_auto_wakeup=False,
            wakeup_probe_enabled=True,
            wakeup_host='',
            wakeup_port=0,
            runtime_mode=runtime_mode,
            stop_event=stop_event,
            progress_callback=progress_callback,
            include_agent_response_metadata=include_agent_response_metadata,
        )
        _check_device_login(config, result)
        result['attempt_index'] = attempt_index
        result['quality'] = quality
        result['authcode_refresh'] = authcode_refresh
        result['admin_token_refresh'] = admin_token_refresh
        result['controller_profile'] = controller_profile
        result['runtime_mode'] = runtime_mode
        all_results.append(result)
        if best_result is None or _score_result(result) > _score_result(best_result):
            best_result = result
        if _result_has_second_video(result):
            break

    if best_result is None:
        raise MonitorCaptureError('no capture result produced')
    selected_attempt_index = int(best_result.get('attempt_index') or 0)
    best_result = dict(best_result)
    best_result['attempts'] = [dict(item) for item in all_results]
    best_result['selected_attempt_index'] = selected_attempt_index
    best_result['attempt_count_total'] = attempt_count
    try:
        _save_relay_cache_server(config, _extract_status_server(best_result))
    except Exception:
        pass

    out_path = _disabled_log_path(config, 'monitor_capture', quality)
    if MONITOR_JSON_LOGS_ENABLED:
        out_name = f'monitor_capture_{quality}_{_timestamp_slug()}.json'
        out_path = config.paths.logs_dir / out_name
        out_path.write_text(json.dumps(best_result, ensure_ascii=False, indent=2), encoding='utf-8')
    return CaptureArtifacts(
        run_json_path=out_path,
        result=best_result,
        quality=quality,
        attempt_count=attempt_count,
    )



def run_monitor_live_stream(
    config: MonitorConfig,
    *,
    quality: str,
    stop_event: threading.Event | None = None,
    status_callback: StatusCallback | None = None,
    data_frame_callback: Callable[[bytes, str], bool | None] | None = None,
    ptz_queue: Any | None = None,
    attempts: int | None = None,
) -> CaptureArtifacts:
    _raise_if_cancelled(stop_event)
    raw_text = _connection_login_text(config)
    serial_number = config.device_id.strip()
    if not serial_number:
        raise MonitorCaptureError('device_id is empty')

    timeout = 20
    refresh_timeout = max(timeout, 12)
    runtime_mode = config.runtime_mode
    controller_profile = config.controller_profile
    controller_stream_type = 'Main'
    handoff_stream_type = _quality_to_handoff_stream_type(quality)
    default_attempt_count = config.attempts if runtime_mode == legacy_cli.RPS_CHAIN_RUNTIME_EXPERIMENTAL else 1
    attempt_count = attempts if attempts is not None else default_attempt_count
    idle_capture_seconds = max(float(config.capture_seconds), 20.0)
    max_frames = max(int(config.max_frames), 65536)
    progress = _StartupProgress(status_callback, total_steps=36)

    authcode, authcode_refresh, admin_token, admin_token_refresh = _load_or_refresh_rps_tokens(
        config,
        raw_text=raw_text,
        serial_number=serial_number,
        refresh_timeout=refresh_timeout,
        runtime_mode=runtime_mode,
        status_callback=status_callback,
        progress_callback=progress.emit,
    )

    _raise_if_cancelled(stop_event)
    chain = _make_rps_chain(config, authcode_refresh)
    encrypted_login_followup = _build_login_followup(serial_number, admin_token, controller_profile, config=config)
    base_client_token = _agent_client_token(config)
    best_result: dict[str, Any] | None = None
    all_results: list[dict[str, Any]] = []
    live_data_seen = False
    cached_servers = _cached_status_servers(config)

    def _wrapped_data_callback(payload: bytes, vekey1: str) -> None:
        nonlocal live_data_seen
        if stop_event is not None and stop_event.is_set():
            return
        meaningful_media = False
        if data_frame_callback is not None:
            meaningful_media = bool(data_frame_callback(payload, vekey1))
        if not meaningful_media:
            return
        if not live_data_seen:
            live_data_seen = True
            progress.set_state('Buffering')
            progress.emit('Live media response first video packet')
            _emit_status(status_callback, 'Live', 'Receiving video')

    for attempt_index in range(1, attempt_count + 1):
        _raise_if_cancelled(stop_event)
        state = 'Connecting' if attempt_index == 1 else 'Retrying'
        progress.set_state(state)
        status_server_override: tuple[str, str] | None = None
        previous_failure = _detect_failure_stage(best_result).get('stage') if isinstance(best_result, dict) else ''
        if previous_failure in {'pub_status_6510', 'pub_status_no_server'} and cached_servers:
            status_server_override = cached_servers[min(attempt_index - 2, len(cached_servers) - 1)]
        if status_server_override:
            _emit_status(
                status_callback,
                state,
                f'Live attempt {attempt_index}/{attempt_count} via cached 6510 {status_server_override[0]}:{status_server_override[1]}',
            )
        else:
            _emit_status(status_callback, state, f'Live attempt {attempt_index}/{attempt_count}')
        session_id = legacy_api.build_session_id()
        progress.emit(f'Live attempt {attempt_index}/{attempt_count} request')
        result = chain.run(
            serial_number=serial_number,
            authcode=authcode,
            status_server_ip=status_server_override[0] if status_server_override else '',
            status_server_port=status_server_override[1] if status_server_override else '',
            client_token=base_client_token,
            session_id=session_id,
            dest_port='34567',
            service_type='RpsCmd',
            encrypt='1',
            step='0',
            protocol_mode='tcp',
            vendor='',
            developer_id='',
            app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
            timeout=timeout,
            channel=0,
            stream_type=controller_stream_type,
            trans_mode='TCP',
            combine_mode='NONE',
            msg_id=0x18,
            code=0x00008505,
            code_endian='be',
            capture_seconds=idle_capture_seconds,
            max_frames=max_frames,
            tcp_mode='encrypted',
            encrypted_session_int=0x1869F,
            encrypted_msg_id=0x30 if controller_profile == 'app_reference_first_6611' else 0x10,
            encrypted_unk=0x63,
            encrypted_cmd=0x0585,
            encrypted_claim_random_a='',
            encrypted_session_hex_width=10,
            encrypted_stream_type=handoff_stream_type,
            encrypted_combine_mode='CONNECT_ALL',
            encrypted_trans_mode='TCP',
            encrypted_followup_frames=[],
            encrypted_followup_delay=0.0,
            encrypted_login_followup=encrypted_login_followup,
            encrypted_controller_auto=True,
            encrypted_controller_profile=controller_profile,
            plain_handoff=True,
            plain_handoff_trigger='after_second_413',
            plain_handoff_stream_type=handoff_stream_type,
            gwm_ams_url='',
            device_oem_id='',
            device_hardware='',
            device_idr_auto_wakeup=False,
            wakeup_probe_enabled=True,
            wakeup_host='',
            wakeup_port=0,
            runtime_mode=runtime_mode,
            stop_event=stop_event,
            plain_handoff_data_frame_callback=_wrapped_data_callback,
            plain_handoff_extend_on_activity=True,
            dynamic_followup_queue=ptz_queue,
            progress_callback=progress.emit,
        )
        _check_device_login(config, result)
        progress.emit(f'Live attempt {attempt_index}/{attempt_count} response {result.get("status") or "unknown"}')
        if status_server_override:
            result['status_server_override'] = f'{status_server_override[0]}:{status_server_override[1]}'
        result['attempt_index'] = attempt_index
        result['quality'] = quality
        result['authcode_refresh'] = authcode_refresh
        result['admin_token_refresh'] = admin_token_refresh
        result['controller_profile'] = controller_profile
        result['runtime_mode'] = runtime_mode
        result['live_data_seen'] = live_data_seen
        all_results.append(result)
        if best_result is None or _score_result(result) > _score_result(best_result):
            best_result = result
        if live_data_seen or _result_has_second_video(result):
            break

    if best_result is None:
        raise MonitorCaptureError('no capture result produced')
    selected_attempt_index = int(best_result.get('attempt_index') or 0)
    best_result = dict(best_result)
    best_result['attempts'] = [dict(item) for item in all_results]
    best_result['selected_attempt_index'] = selected_attempt_index
    best_result['attempt_count_total'] = attempt_count
    try:
        _save_relay_cache_server(config, _extract_status_server(best_result))
    except Exception:
        pass

    out_path = _disabled_log_path(config, 'monitor_live', quality)
    if MONITOR_JSON_LOGS_ENABLED:
        out_name = f'monitor_live_{quality}_{_timestamp_slug()}.json'
        out_path = config.paths.logs_dir / out_name
        out_path.write_text(json.dumps(_summarize_live_result(best_result), ensure_ascii=False, indent=2), encoding='utf-8')
    return CaptureArtifacts(
        run_json_path=out_path,
        result=best_result,
        quality=quality,
        attempt_count=attempt_count,
    )

