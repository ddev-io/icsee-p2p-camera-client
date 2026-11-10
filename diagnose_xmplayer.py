from __future__ import annotations

import json
import multiprocessing
import queue
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import os
import urllib.parse
import urllib.request
from pathlib import Path

from xmplayer.config.loader import load_monitor_config, validate_cloud_login_file
from xmplayer.core import legacy_api
from xmplayer.core.service import (
    _alarm_service_hosts,
    _cache_machine_id,
    _load_or_refresh_rps_tokens,
    describe_capture_failure,
    fetch_device_recordings,
    fetch_monitor_messages,
    run_monitor_capture,
    summarize_live_probe_failure,
)


def _ok(label: str, detail: str = '') -> str:
    return f'OK   {label}' + (f': {detail}' if detail else '')


def _fail(label: str, detail: str) -> str:
    return f'FAIL {label}: {detail}'


def _warn(label: str, detail: str) -> str:
    return f'WARN {label}: {detail}'


def _tcp_check(host: str, port: int, timeout: float = 4.0) -> str:
    start = time.time()
    try:
        connector = getattr(legacy_api, '_create_tcp_connection', None)
        if callable(connector):
            sock_ctx = connector((host, int(port)), timeout=timeout)
        else:
            sock_ctx = socket.create_connection((host, int(port)), timeout=timeout)
        with sock_ctx as sock:
            local = sock.getsockname()
            local_text = f' local={local[0]}:{local[1]}' if local else ''
            via = ' via=socks5' if str(os.environ.get('XMPLAYER_SOCKS5_PROXY') or os.environ.get('SOCKS5_PROXY') or '').strip() else ''
            return _ok(f'tcp {host}:{port}', f'{time.time() - start:.2f}s{local_text}{via}')
    except Exception as exc:
        return _fail(f'tcp {host}:{port}', str(exc))


def _public_ip_check(*, use_system_proxy: bool, timeout: float = 5.0) -> str:
    label = 'public ip system-proxy' if use_system_proxy else 'public ip direct'
    urls = ('https://api.ipify.org', 'https://ifconfig.me/ip')
    context = ssl._create_unverified_context()
    if use_system_proxy:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    else:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
        )
    last_error = ''
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'xmplayer-diagnostics'})
            with opener.open(req, timeout=timeout) as response:
                text = response.read(80).decode('ascii', errors='ignore').strip()
            if text:
                return _ok(label, text)
        except Exception as exc:
            last_error = str(exc)
    return _warn(label, last_error or 'unavailable')


def _public_ip_socks_check(timeout: float = 5.0) -> str:
    proxy = str(os.environ.get('XMPLAYER_SOCKS5_PROXY') or os.environ.get('SOCKS5_PROXY') or '').strip()
    if not proxy:
        return ''
    result = legacy_api.http_text(
        url='https://api.ipify.org',
        method='GET',
        payload=None,
        headers={'User-Agent': 'xmplayer-diagnostics'},
        timeout=int(timeout),
        ssl_verify=False,
    )
    if result.ok and result.text.strip():
        return _ok('public ip socks5', result.text.strip()[:80])
    return _warn('public ip socks5', result.error or f'status={result.status}')


def _details_have_handshake(details: dict) -> bool:
    enc = details.get('encrypted_probe') if isinstance(details.get('encrypted_probe'), dict) else {}
    if enc.get('handshake_ok') is True:
        return True
    retries = details.get('selector_retries') if isinstance(details.get('selector_retries'), list) else []
    return any(isinstance(item, dict) and item.get('handshake') is True for item in retries)


def _emit(rows: list[str], root: Path, line: str) -> None:
    rows.append(line)
    print(line, flush=True)
    try:
        (root / 'diagnostics.txt').write_text('\n'.join(rows) + '\n', encoding='utf-8')
    except Exception:
        pass


def _compact_dict(value: object, limit: int = 160) -> str:
    if not isinstance(value, dict) or not value:
        return ''
    parts = [f'{key}={val}' for key, val in value.items() if val not in (None, '', {}, [])]
    text = ' '.join(parts)
    return text[: limit - 3] + '...' if len(text) > limit else text


def _emit_live_probe_details(rows: list[str], root: Path, result: dict) -> dict:
    details = summarize_live_probe_failure(result)
    protocol = details.get('agent_protocol') if isinstance(details.get('agent_protocol'), dict) else {}
    server_info = details.get('agent_server') if isinstance(details.get('agent_server'), dict) else {}
    enc = details.get('encrypted_probe') if isinstance(details.get('encrypted_probe'), dict) else {}
    server = str(server_info.get('server') or protocol.get('agent_server') or '').strip()
    _emit(
        rows,
        root,
        'INFO live agent: '
        f"selected={protocol.get('selected')} attempts={protocol.get('attempts')} "
        f"server={server or '-'} mode={server_info.get('protocol_mode') or '-'}",
    )
    responses = protocol.get('responses') if isinstance(protocol.get('responses'), list) else []
    for response in responses:
        random_info = response.get('random_str') or {}
        length = random_info.get('length')
        _emit(
            rows, root,
            f"INFO AgentProtocol response #{response.get('index')}: "
            f"selected={response.get('selected')} http={response.get('http_status')} "
            f"ok={response.get('http_ok')} "
            f"message={json.dumps(response.get('message_type') or '', ensure_ascii=False)} "
            f"ErrorNum={json.dumps(response.get('error_num') or '', ensure_ascii=False)} "
            f"ErrorString={json.dumps(response.get('error_string') or '', ensure_ascii=False)} "
            f"ProtocolMode={json.dumps(response.get('protocol_mode') or '', ensure_ascii=False)} "
            f"RandomStr.present={random_info.get('present')} "
            f"RandomStr.type={random_info.get('type') or 'missing'} "
            f"RandomStr.length={length if length is not None else '-'}",
        )
        _emit(
            rows, root,
            f"INFO AgentProtocol fields #{response.get('index')}: "
            f"types={response.get('response_type')}/{response.get('agent_type')}/"
            f"{response.get('header_type')}/{response.get('body_type')} "
            + json.dumps(response.get('fields') or {}, ensure_ascii=False),
        )
        if response.get('transport_error'):
            _emit(rows, root, f"INFO AgentProtocol transport #{response.get('index')}: {response['transport_error']}")
    if protocol.get('responses_omitted'):
        _emit(rows, root, f"INFO AgentProtocol: {protocol['responses_omitted']} additional responses omitted")
    if server and ':' in server:
        host, port = server.rsplit(':', 1)
        if port.isdigit():
            _emit(rows, root, _tcp_check(host, int(port), timeout=3.0))
    frames = enc.get('frames') if isinstance(enc.get('frames'), dict) else {}
    frame_text = (
        f"total={frames.get('total', 0)} control={frames.get('control', 0)} "
        f"data={frames.get('data', 0)} exit={frames.get('exit_reason') or '-'}"
    )
    cmd_text = _compact_dict(enc.get('cmd_counts'), limit=120)
    first_cmds = enc.get('first_cmds') if isinstance(enc.get('first_cmds'), list) else []
    _emit(
        rows,
        root,
        'INFO first6611: '
        f"endpoint={enc.get('endpoint') or '-'} status={enc.get('status') or '-'} "
        f"encoding={enc.get('stream_encoding') or '-'} "
        f"handshake={enc.get('handshake_ok')} h_err={enc.get('handshake_error') or '-'} "
        f"err={enc.get('error') or '-'} {frame_text}",
    )
    if cmd_text or first_cmds:
        _emit(rows, root, f"INFO first6611 frames: cmds={cmd_text or '-'} first={','.join(str(x) for x in first_cmds[:8]) or '-'}")
    retries = details.get('selector_retries') if isinstance(details.get('selector_retries'), list) else []
    if retries:
        retry_parts = []
        for item in retries[:32]:
            if not isinstance(item, dict):
                continue
            retry_parts.append(
                f"{item.get('i')}:{item.get('token') or '-'}@{item.get('server') or '-'}"
                f"->h={item.get('handshake')} c={item.get('control') or 0} d={item.get('data') or 0} s={item.get('status') or '-'}"
            )
        if retry_parts:
            for idx in range(0, len(retry_parts), 8):
                _emit(rows, root, 'INFO first6611 retries: ' + ' | '.join(retry_parts[idx:idx + 8]))
    second = details.get('second_6611') if isinstance(details.get('second_6611'), dict) else {}
    if second:
        _emit(
            rows,
            root,
            'INFO second6611: '
            f"status={second.get('status') or '-'} ret={second.get('ret')} "
            f"frames={_compact_dict(second.get('frames'), limit=120) or '-'}",
        )
    return details


def _live_control_probe_worker(config, events, rotate_client: bool) -> None:
    # A separate process lets the report stop even if DNS or a socket call
    # ignores the cooperative stop_event. Only this worker is terminated.
    if rotate_client:
        os.environ['ICSEE_ROTATE_AGENT_CLIENT_ON_RETRY'] = '1'
    try:
        capture = run_monitor_capture(
            config, quality=config.default_quality, attempts=1,
            timeout=8, capture_seconds=6.0, max_frames=32,
            progress_callback=lambda detail: events.put(('progress', detail)),
            include_agent_response_metadata=True,
        )
        events.put(('result', capture.result))
    except Exception as exc:
        detail = legacy_api.summarize_agent_response(
            None, transport_error=f'{type(exc).__name__}: {exc}',
        )['transport_error']
        events.put(('error', detail))


def _run_live_control_probe(config, rows: list[str], root: Path, *, rotate_client: bool = False) -> dict:
    context = multiprocessing.get_context('spawn')
    events = context.Queue()
    process = context.Process(
        target=_live_control_probe_worker, args=(config, events, rotate_client), daemon=True,
    )
    limit = 70.0
    started = time.monotonic()
    last_update = started
    last_stage = 'starting worker'
    process_started = False
    try:
        process.start()
        process_started = True
        while True:
            now = time.monotonic()
            remaining = limit - (now - started)
            if remaining <= 0:
                raise TimeoutError(
                    f'{limit:.0f}s limit reached; worker stopped. '
                    f'Last stage: {last_stage}. Partial diagnostics have been saved.'
                )
            try:
                kind, value = events.get(timeout=min(2.0, remaining))
            except queue.Empty:
                if not process.is_alive():
                    raise RuntimeError(f'live probe worker exited with code {process.exitcode} without a result')
                now = time.monotonic()
                if now - last_update >= 10.0:
                    _emit(rows, root, f'INFO live progress {now - started:.1f}s: waiting; last stage: {last_stage}')
                    last_update = now
                continue
            if kind == 'result':
                return value
            if kind == 'error':
                raise RuntimeError(value)
            if kind == 'progress':
                # Metadata is already allowlisted/redacted by the transport.
                # Preserve it immediately if the later TCP probe times out.
                if not value.startswith('AgentProtocol response metadata '):
                    last_stage = value
                _emit(rows, root, f'INFO live progress {time.monotonic() - started:.1f}s: {value}')
                last_update = time.monotonic()
    finally:
        if process_started:
            if process.is_alive():
                process.terminate()
            process.join(timeout=3.0)
            if process.is_alive():
                process.kill()
                process.join(timeout=3.0)
            if not process.is_alive():
                process.close()
        events.close()


def main() -> int:
    rows: list[str] = []
    root = Path(__file__).resolve().parent
    _emit(rows, root, f'xmplayer diagnostics')
    _emit(rows, root, f'project: {root}')
    _emit(rows, root, f'python: {sys.executable}')
    _emit(rows, root, f'version: {sys.version.split()[0]}')
    _emit(rows, root, f'machine_id: {_cache_machine_id()}')
    proxies = urllib.request.getproxies()
    socks_proxy = str(os.environ.get('XMPLAYER_SOCKS5_PROXY') or os.environ.get('SOCKS5_PROXY') or '').strip()
    if socks_proxy:
        _emit(rows, root, _ok('socks5 proxy', socks_proxy))
        socks_ip = _public_ip_socks_check()
        if socks_ip:
            _emit(rows, root, socks_ip)
    if proxies and str(os.environ.get('XMPLAYER_USE_SYSTEM_PROXY') or '').strip() != '1':
        proxy_keys = ','.join(sorted(str(key) for key in proxies.keys()))
        _emit(rows, root, _warn('system proxy', f'detected {proxy_keys}; xmplayer HTTP uses direct/no-proxy by default'))
        _emit(rows, root, _public_ip_check(use_system_proxy=False))
        _emit(rows, root, _public_ip_check(use_system_proxy=True))
    elif proxies:
        _emit(rows, root, _warn('system proxy', 'XMPLAYER_USE_SYSTEM_PROXY=1, using system proxy'))
        _emit(rows, root, _public_ip_check(use_system_proxy=False))
        _emit(rows, root, _public_ip_check(use_system_proxy=True))
    else:
        _emit(rows, root, _ok('system proxy', 'none'))
        _emit(rows, root, _public_ip_check(use_system_proxy=False))

    try:
        cfg = load_monitor_config()
        _emit(rows, root, _ok('config', str(cfg.config_path)))
    except Exception as exc:
        _emit(rows, root, _fail('config', str(exc)))
        return _finish(rows, root)

    login_issue = validate_cloud_login_file(cfg.cloud_login_file)
    _emit(rows, root, _fail('login.txt', login_issue) if login_issue else _ok('login.txt', str(cfg.cloud_login_file)))

    try:
        import tkinter  # noqa: F401

        _emit(rows, root, _ok('tkinter'))
    except Exception as exc:
        _emit(rows, root, _fail('tkinter', str(exc)))

    try:
        from PIL import Image  # noqa: F401

        _emit(rows, root, _ok('Pillow'))
    except Exception as exc:
        _emit(rows, root, _fail('Pillow', str(exc)))

    try:
        from Crypto.Cipher import AES  # noqa: F401

        _emit(rows, root, _ok('pycryptodome'))
    except Exception as exc:
        _emit(rows, root, _fail('pycryptodome', str(exc)))

    ffmpeg = Path(cfg.ffmpeg_path)
    ffmpeg_path = str(ffmpeg if ffmpeg.is_absolute() else (cfg.project_root / cfg.ffmpeg_path))
    if Path(ffmpeg_path).exists() or shutil.which(cfg.ffmpeg_path):
        try:
            result = subprocess.run([ffmpeg_path, '-version'], capture_output=True, text=True, timeout=6)
            first_line = (result.stdout or result.stderr).splitlines()[0] if (result.stdout or result.stderr) else ''
            _emit(rows, root, _ok('ffmpeg', first_line))
        except Exception as exc:
            _emit(rows, root, _fail('ffmpeg', str(exc)))
    else:
        _emit(rows, root, _fail('ffmpeg', ffmpeg_path))

    _emit(rows, root, _tcp_check('pub-status.secu100.net', 7605))
    _emit(rows, root, _tcp_check('45.255.134.177', 6502))
    try:
        client_token = str(getattr(cfg, 'agent_client_id', '') or '').strip() or legacy_api.get_agent_client_uuid()
        token_source = 'config' if str(getattr(cfg, 'agent_client_id', '') or '').strip() else 'cache'
        _emit(rows, root, _ok('agent client id', f'{client_token[:8]}...{client_token[-4:]} source={token_source}'))
    except Exception as exc:
        _emit(rows, root, _fail('agent client id', str(exc)))
    for host in _alarm_service_hosts()[:2]:
        parsed = urllib.parse.urlparse(host)
        _emit(rows, root, _tcp_check(parsed.hostname or host, parsed.port or 6502))

    if not login_issue:
        raw_text = cfg.cloud_login_file.read_text(encoding='utf-8-sig', errors='ignore')
        try:
            _emit(rows, root, 'RUN  cloud token load/refresh...')
            authcode, auth_info, _admin_token, admin_info = _load_or_refresh_rps_tokens(
                cfg,
                raw_text=raw_text,
                serial_number=cfg.device_id,
                refresh_timeout=12,
                runtime_mode=cfg.runtime_mode,
                status_callback=None,
            )
            _emit(rows, root, _ok('cloud token load/refresh',
                  f"auth={auth_info.get('mode', '')} admin={admin_info.get('mode', '')} "
                  f"ams={auth_info.get('ams_base') or admin_info.get('ams_base') or 'auto'}"))
            _emit(rows, root, 'RUN  pub-status query...')
            status = legacy_api.status_protocol_query(
                serial_number=cfg.device_id,
                authcode=authcode,
                base=legacy_api.DEFAULT_STATUS_BASE,
                timeout=12,
                ssl_verify=False,
                user_agent=legacy_api.DEFAULT_STATUS_UA,
                content_type='text/html',
            )
            parsed = legacy_api.parse_status_protocol_response(status.json_data)
            server = ''
            body = parsed.get('body') if isinstance(parsed.get('body'), list) else []
            if body and isinstance(body[0], dict):
                host = str(body[0].get('ServerIP') or '').strip()
                port = str(body[0].get('ServerPort') or '').strip()
                if host and port:
                    server = f'{host}:{port}'
            if status.ok and server:
                _emit(rows, root, _ok('pub-status query', server))
            else:
                status_text = ''
                if body and isinstance(body[0], dict):
                    status_text = str(body[0].get('Status') or '').strip()
                detail = status.error or str(parsed)
                if status.ok and status_text and not server:
                    detail = f'Status={status_text}; no ServerIP/ServerPort'
                _emit(rows, root, _fail('pub-status query', detail))
            if server and ':' in server:
                host, port = server.rsplit(':', 1)
                _emit(rows, root, _tcp_check(host, int(port)))
        except Exception as exc:
            _emit(rows, root, _fail('cloud token/status', str(exc)))

        try:
            _emit(rows, root, 'RUN  live control probe (70s limit, progress updates)...')
            result = _run_live_control_probe(cfg, rows, root)
            failure = describe_capture_failure(result)
            if failure:
                _emit(rows, root, _fail('live control probe', failure))
                details = _emit_live_probe_details(rows, root, result)
                if not _details_have_handshake(details):
                    try:
                        _emit(rows, root, 'RUN  live control probe rotating-client-token (70s limit, progress updates)...')
                        rotate_result = _run_live_control_probe(cfg, rows, root, rotate_client=True)
                        rotate_failure = describe_capture_failure(rotate_result)
                        if rotate_failure:
                            _emit(rows, root, _fail('live control probe rotating-client-token', rotate_failure))
                        else:
                            _emit(rows, root, _ok('live control probe rotating-client-token', 'first/second 6611 returned media-capable result'))
                        _emit_live_probe_details(rows, root, rotate_result)
                    except Exception as exc:
                        _emit(rows, root, _fail('live control probe rotating-client-token', str(exc)))
            else:
                _emit(rows, root, _ok('live control probe', 'first/second 6611 returned media-capable result'))
                _emit_live_probe_details(rows, root, result)
        except Exception as exc:
            _emit(rows, root, _fail('live control probe', str(exc)))

        try:
            _emit(rows, root, 'RUN  recordings query...')
            recording_stop = threading.Event()
            timer = threading.Timer(28.0, recording_stop.set)
            timer.daemon = True
            timer.start()
            records, meta = fetch_device_recordings(cfg, timeout=8, max_pages=1, stop_event=recording_stop)
            timer.cancel()
            _emit(rows, root, _ok('recordings query', f"count={len(records)} pages={meta.get('page_count')} ret={meta.get('response_ret')}"))
        except Exception as exc:
            try:
                timer.cancel()
            except Exception:
                pass
            _emit(rows, root, _fail('recordings query', str(exc)))

        try:
            _emit(rows, root, 'RUN  messages query...')
            messages, meta = fetch_monitor_messages(cfg, limit=1, timeout=12)
            _emit(rows, root, _ok('messages query', f"count={len(messages)} warning={meta.get('warning') or ''}"))
            image_url = ''
            for msg in messages:
                image_url = msg.image_url or (msg.image_urls[0] if msg.image_urls else '')
                if image_url:
                    break
            if image_url:
                req = urllib.request.Request(image_url, headers={'User-Agent': 'xmplayer'})
                context = ssl._create_unverified_context() if str(image_url).lower().startswith('https://') else None
                with urllib.request.urlopen(req, timeout=8, context=context) as response:
                    data = response.read(32)
                _emit(rows, root, _ok('message image url', f'{len(data)} bytes head'))
            else:
                _emit(rows, root, _warn('message image url', 'no image URL in first message'))
        except Exception as exc:
            _emit(rows, root, _fail('messages/images', str(exc)))

    return _finish(rows, root)


def _finish(rows: list[str], root: Path) -> int:
    text = '\n'.join(rows) + '\n'
    path = root / 'diagnostics.txt'
    try:
        path.write_text(text, encoding='utf-8')
        print(f'wrote: {path}')
    except Exception:
        pass
    return 0 if not any(row.startswith('FAIL') for row in rows) else 1


if __name__ == '__main__':
    multiprocessing.freeze_support()
    raise SystemExit(main())
