from __future__ import annotations

import copy
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any

from ..config.loader import MonitorConfig
from . import legacy_api, legacy_cli, service

WIFI_CONFIG = 'NetWork.Wifi'
WIFI_SCAN = 'WifiAP'
GET_CONFIG = 0x0412
SET_CONFIG = 0x0410
SCAN_WIFI = 0x03FC


@dataclass(frozen=True, slots=True)
class WifiNetwork:
    ssid: str
    auth: str = ''
    encryption: str = ''
    channel: int = 0
    signal: str = ''


@dataclass(slots=True)
class CameraWifi:
    current_ssid: str
    networks: list[WifiNetwork]
    scan_error: str = ''
    # This can contain the current password. Never serialize it or log its repr.
    _config: dict[str, Any] = field(default_factory=dict, repr=False)


class WifiSaveUnconfirmed(service.MonitorCaptureError):
    """A write was attempted, but the camera's acknowledgement was not received."""


def wifi_network_security(network: WifiNetwork) -> str:
    auth = network.auth.upper()
    encryption = network.encryption.upper()
    if auth == 'OPEN' and encryption in {'', 'NONE'}:
        return 'Open'
    if 'WPA2' in auth and encryption in {'AES', 'TKIPAES', 'TKIP+AES'}:
        return 'WPA2'
    return 'Unsupported'


def _decode_ssid(value: Any) -> str:
    text = str(value or '')
    # The SDK returns non-ASCII SSID bytes as literal \xNN sequences. Decode
    # just these sequences: URL decoding would corrupt names containing % or +.
    def decode(match: re.Match[str]) -> str:
        raw = bytes(int(v, 16) for v in re.findall(r'\\x([0-9a-fA-F]{2})', match[0]))
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return match[0]
    return re.sub(r'(?:\\x[0-9a-fA-F]{2})+', decode, text)


def parse_wifi_networks(response: dict[str, Any]) -> list[WifiNetwork]:
    body = response.get(WIFI_SCAN)
    rows = body.get(WIFI_SCAN) if isinstance(body, dict) else body
    if rows is None and isinstance(body, dict) and body.get('Numbers') == 0:
        return []
    if not isinstance(rows, list):
        raise service.MonitorCaptureError('Camera returned an invalid Wi-Fi network list')
    networks: list[WifiNetwork] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        ssid = _decode_ssid(row.get('SSID'))
        if not ssid:
            continue
        auth = str(row.get('Auth') or '')
        encryption = str(row.get('EncrypType') or '')
        key = (ssid, auth, encryption)
        if key in seen:
            continue
        seen.add(key)
        networks.append(WifiNetwork(
            ssid=ssid,
            auth=auth,
            encryption=encryption,
            channel=service._parse_intish(row.get('Channel')),
            signal=str(row.get('RSSI') if row.get('RSSI') is not None else row.get('nRSSI', '')),
        ))
    return networks


def build_wifi_config(current: dict[str, Any], ssid: str, password: str) -> dict[str, Any]:
    if not isinstance(current, dict) or not current:
        raise ValueError('Load the camera Wi-Fi settings before saving')
    # Spaces in both SSIDs and passwords are significant.
    if not isinstance(ssid, str) or not 1 <= len(ssid.encode('utf-8')) <= 32 or '\x00' in ssid:
        raise ValueError('Wi-Fi name must contain 1 to 32 UTF-8 bytes and no NUL characters')
    if not isinstance(password, str) or '\x00' in password:
        raise ValueError('Wi-Fi password must not contain NUL characters')
    if password and not (
        8 <= len(password.encode('utf-8')) <= 63
        or re.fullmatch(r'[0-9a-fA-F]{64}', password)
    ):
        raise ValueError('WPA2 password must contain 8 to 63 bytes, or 64 hexadecimal characters')
    result = copy.deepcopy(current)
    # Matches CConfigAPDev::OnMsg in the iCSee SDK: preserve IP settings and
    # other firmware fields, enable Wi-Fi, use ASCII keys (KeyType=1).
    result.update({
        'SSID': ssid,
        'Keys': password,
        'Enable': True,
        'KeyType': 1,
        'Auth': 'WPA2' if password else 'OPEN',
        'EncrypType': 'AES' if password else 'NONE',
    })
    return result


def _find_response(result: dict[str, Any], name: str, cmd: int) -> dict[str, Any] | None:
    probe = result.get('tcp_encrypted_probe') or result
    frames = (probe.get('frames') or {}).get('control_frames') or []
    for frame in frames:
        if not isinstance(frame, dict) or service._parse_intish(frame.get('cmd')) != cmd + 1:
            continue
        data = service._control_frame_json(frame)
        if data and (data.get('Name') == name or name in data):
            return data
    return None


def _command(
    config: MonitorConfig,
    name: str,
    cmd: int,
    *,
    body: dict[str, Any] | None = None,
    timeout: int = 20,
    stop_event: threading.Event | None = None,
) -> dict[str, Any]:
    service._raise_if_cancelled(stop_event)
    login_text = service._connection_login_text(config)
    serial = config.device_id.strip()
    if not serial:
        raise service.MonitorCaptureError('Select a camera before configuring Wi-Fi')
    authcode, _auth_info, admin_token, _admin_info = service._load_or_refresh_rps_tokens(
        config,
        raw_text=login_text,
        serial_number=serial,
        refresh_timeout=max(timeout, 12),
        runtime_mode=config.runtime_mode,
        status_callback=None,
    )
    payload: dict[str, Any] = {'Name': name, 'SessionID': '{{SESSION_ID}}'}
    if body is not None:
        payload[name] = body
    followup = {
        'send_phase': 'post_login', 'msg_type': 0, 'session_id': 0,
        'msg_id': 0x48, 'unk': 0, 'cmd': cmd, 'code': 0, 'code_endian': 'be',
        'plain_payload_text': json.dumps(payload, ensure_ascii=False, separators=(',', ':')),
        'delay_before': 0.2, 'stop_after_response_cmd': cmd + 1,
    }
    chain = service._make_rps_chain(config, _auth_info)
    servers = service._recording_server_attempts(service._cached_status_servers(config, limit=2), None)
    # A lost response to a Wi-Fi write may mean the camera already switched
    # networks. Never send the write a second time automatically.
    if body is not None:
        servers = [('', '')]
    last_failure = ''
    for host, port in servers:
        service._raise_if_cancelled(stop_event)
        result = chain.run(
            serial_number=serial, authcode=authcode,
            status_server_ip=host, status_server_port=port,
            client_token=service._agent_client_token(config),
            session_id=legacy_api.build_session_id(), dest_port='34567',
            service_type='RpsCmd', encrypt='1', step='0', protocol_mode='tcp',
            vendor='', developer_id='', app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
            timeout=max(timeout, 12), channel=0, stream_type='Main', trans_mode='TCP',
            combine_mode='NONE', msg_id=0x18, code=0x00008505, code_endian='be',
            capture_seconds=12.0, max_frames=512, tcp_mode='encrypted',
            encrypted_session_int=0x1869F,
            encrypted_msg_id=0x30 if config.controller_profile == 'app_reference_first_6611' else 0x10,
            encrypted_unk=0x63, encrypted_cmd=0x0585, encrypted_claim_random_a='',
            encrypted_session_hex_width=10, encrypted_stream_type='Extra1',
            encrypted_combine_mode='CONNECT_ALL', encrypted_trans_mode='TCP',
            encrypted_followup_frames=[followup], encrypted_followup_delay=0.0,
            encrypted_login_followup=service._build_login_followup(serial, admin_token, config.controller_profile, config=config),
            encrypted_controller_auto=False, encrypted_controller_profile=config.controller_profile,
            plain_handoff=False, runtime_mode=config.runtime_mode, stop_event=stop_event,
        )
        service._check_device_login(config, result)
        response = _find_response(result, name, cmd)
        if response is not None:
            ret = response.get('Ret')
            if ret is None or service._parse_intish(ret) not in (0, 100):
                raise service.MonitorCaptureError(f'Camera rejected {name}: Ret={ret}')
            return response
        last_failure = service.describe_capture_failure(result) or f'No {name} response received'
    if body is not None:
        raise WifiSaveUnconfirmed(
            'No save acknowledgement received. The camera may already have switched Wi-Fi. '
            'Wait for it to reconnect, then refresh the settings before trying again.'
        )
    raise service.MonitorCaptureError(last_failure)


def read_camera_wifi(config: MonitorConfig, *, stop_event: threading.Event | None = None) -> CameraWifi:
    response = _command(config, WIFI_CONFIG, GET_CONFIG, stop_event=stop_event)
    current = response.get(WIFI_CONFIG)
    if not isinstance(current, dict) or not current:
        raise service.MonitorCaptureError('Camera does not expose NetWork.Wifi settings')
    settings = CameraWifi(current_ssid=_decode_ssid(current.get('SSID')), networks=[], _config=current)
    try:
        settings.networks = parse_wifi_networks(_command(config, WIFI_SCAN, SCAN_WIFI, stop_event=stop_event))
    except service.MonitorCancelled:
        raise
    except service.MonitorCaptureError as exc:
        settings.scan_error = str(exc)
    return settings


def save_camera_wifi(
    config: MonitorConfig,
    settings: CameraWifi,
    network: WifiNetwork,
    password: str,
    *,
    stop_event: threading.Event | None = None,
) -> None:
    if network not in settings.networks:
        raise ValueError('Choose a network from the latest camera scan')
    security = wifi_network_security(network)
    if security == 'Unsupported':
        raise ValueError('Choose a WPA2/AES or open network supported by the camera')
    if security == 'WPA2' and not password:
        raise ValueError('Enter the password for the selected Wi-Fi network')
    if security == 'Open':
        password = ''
    body = build_wifi_config(settings._config, network.ssid, password)
    try:
        _command(config, WIFI_CONFIG, SET_CONFIG, body=body, stop_event=stop_event)
    finally:
        # The write may have changed the network even without an acknowledgement.
        # Require a fresh read before another write and discard the old password.
        body.clear()
        settings._config.clear()
