"""Account-free Cloud ID discovery. No SDK, account token, or login.txt is used.

The native DevAuthQuery request was reconstructed from libFunSDK ARM code:
DevAuthQuery @ A0EB2C, GetPlatHttpPtl @ A0F4B4, GetEncryptStr @ A23164.
Device password authentication is verified after a usable RPS route is found.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import re
from typing import Any, Callable

from . import legacy_api as api
from .legacy_signature import compute_signature


DEFAULT_AUTH_BASE = 'https://rs.xmeye.net'
SERVICES = ('dss', 'rps', 'p2p', 'css', 'tps', 'pms')


class CloudIdError(RuntimeError):
    """Safe error identifiers, without request URLs, bodies or server messages."""

    def __init__(self, stage: str, reason: str, code: int | str | None = None):
        self.stage = stage
        self.reason = reason
        self.code = code
        super().__init__(f'{stage}: {reason}' + (f' ({code})' if code is not None else ''))


@dataclass(frozen=True)
class AppIdentity:
    # Public application identity already used by the client's pre-login flow.
    uuid: str = 'xmeye'
    app_key: str = '6475da8c43534b8a8c2813e362dda1cb'
    secret: str = field(default='067f8673c2e94d38905dd426ca3a3bfc', repr=False)
    move_card: int = 2


@dataclass(frozen=True)
class ServiceCodes:
    serial_number: str = field(repr=False)
    codes: dict[str, str] = field(repr=False)

    def for_service(self, service: str) -> str:
        value = self.codes.get(service, '')
        if not value:
            raise CloudIdError('auth', 'missing_service_code')
        return value

    def available_services(self) -> list[str]:
        return sorted(k for k, v in self.codes.items() if v)


@dataclass(frozen=True)
class DeviceStatus:
    status: str
    service: str
    message_type: str
    entry: dict[str, Any] = field(repr=False)

    def safe_summary(self) -> dict[str, Any]:
        return {'device_status': self.status, 'service': self.service,
                'message_type': self.message_type,
                'relay_advertised': bool(self.entry.get('ServerIP') and self.entry.get('ServerPort'))}


def validate_cloud_id(value: str) -> str:
    value = str(value or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9]{8,64}', value):
        raise CloudIdError('input', 'invalid_cloud_id')
    return value


def _transport_error(stage: str, response: api.HttpResult) -> CloudIdError:
    reason = ('tls_verification_failed' if 'CERTIFICATE_VERIFY_FAILED' in str(response.error)
              else 'transport_error')
    return CloudIdError(stage, reason, response.status)


class CloudIdClient:
    def __init__(self, *, identity: AppIdentity | None = None,
                 auth_base: str = DEFAULT_AUTH_BASE,
                 status_base: str = api.DEFAULT_STATUS_BASE,
                 timeout: int = 7, ssl_verify: bool = True):
        self.identity = identity or AppIdentity()
        self.auth_base = auth_base.rstrip('/')
        self.status_base = status_base
        self.timeout = max(1, int(timeout))
        self.ssl_verify = ssl_verify

    def auth_codes(self, cloud_id: str) -> ServiceCodes:
        sn = validate_cloud_id(cloud_id)
        ident = self.identity
        timestamp = api._next_ams_time_millis()
        signature = compute_signature(ident.uuid, ident.app_key, ident.secret,
                                      timestamp, ident.move_card)
        key = api._derive_ams_response_key(timestamp, ident.secret)
        # SDK uses the literal "uuids=%s", not account/Authorization parameters.
        body = api._encrypt_ams_hex_payload('uuids=' + sn, key)
        response = api.http_text(
            url=f'{self.auth_base}/acquery/v3/{timestamp}/{signature}.rs',
            payload=body, timeout=self.timeout, ssl_verify=self.ssl_verify,
            headers={'appKey': ident.app_key, 'uuid': ident.uuid,
                     'Content-Type': 'application/x-www-form-urlencoded',
                     'Accept': '*/*', 'Accept-Charset': 'utf-8',
                     'User-Agent': api.DEFAULT_STATUS_UA},
        )
        if not response.ok:
            raise _transport_error('auth', response)
        try:
            payload = json.loads(api._decrypt_ams_hex_payload(response.text, key))
        except (ValueError, TypeError, UnicodeError):
            raise CloudIdError('auth', 'invalid_encrypted_response') from None
        if not isinstance(payload, dict):
            raise CloudIdError('auth', 'invalid_response')
        code = payload.get('code')
        if str(code) != '2000':
            # Server messages may repeat the Cloud ID or authentication data.
            safe_code = str(code) if re.fullmatch(r'-?\d{1,10}', str(code)) else None
            raise CloudIdError('auth', 'server_rejected', safe_code)
        rows = payload.get('data')
        if not isinstance(rows, list):
            raise CloudIdError('auth', 'missing_devices')
        matches = [r for r in rows if isinstance(r, dict) and r.get('uuid') == sn]
        if len(matches) != 1:
            raise CloudIdError('auth', 'device_not_matched')
        codes = {k: v for k, v in matches[0].items()
                 if k in SERVICES and isinstance(v, str) and v}
        if not codes:
            raise CloudIdError('auth', 'missing_service_codes')
        return ServiceCodes(sn, codes)

    def device_status(self, codes: ServiceCodes, *, service: str = 'rps',
                      multi: bool = False) -> DeviceStatus:
        request_type = 'MSG_STATUS_MULTIQUERY_REQ' if multi else 'MSG_STATUS_LOCALQUERY_REQ'
        expected_type = request_type.removesuffix('_REQ') + '_RSP'
        response = api.status_protocol_query(
            serial_number=codes.serial_number, authcode=codes.for_service(service),
            base=self.status_base, timeout=self.timeout, ssl_verify=self.ssl_verify,
            message_type=request_type,
        )
        if not response.ok:
            raise _transport_error('status', response)
        parsed = api.parse_status_protocol_response(response.json_data)
        if parsed.get('message_type') != expected_type:
            raise CloudIdError('status', 'unexpected_message_type')
        header = (response.json_data.get('StatusProtocol') or {}).get('Header') or {}
        if str(header.get('CSeq')) != '1':
            raise CloudIdError('status', 'sequence_mismatch')
        code = parsed.get('error_num')
        if str(code) != '200':
            safe_code = str(code) if re.fullmatch(r'-?\d{1,10}', str(code)) else None
            raise CloudIdError('status', 'server_rejected', safe_code)
        matches = [r for r in parsed.get('body', []) if isinstance(r, dict)
                   and r.get('SerialNumber') == codes.serial_number]
        if len(matches) != 1:
            raise CloudIdError('status', 'device_not_matched')
        entry = matches[0]
        status = entry.get('Status')
        if status not in ('Online', 'Offline'):
            raise CloudIdError('status', 'unknown_device_status')
        return DeviceStatus(status, service, expected_type, entry)

    def discover_status(self, codes: ServiceCodes, *, service: str = 'rps') -> DeviceStatus:
        local = self.device_status(codes, service=service)
        if local.status == 'Online':
            return local
        # Observed on the same fresh codes: LOCALQUERY can return Offline while
        # MULTIQUERY returns Online and the usable RPS route.
        return self.device_status(codes, service=service, multi=True)

    def probe_login(self, cloud_id: str, *, username: str, password: str,
                    channel: int = 0, capture_seconds: float = 4,
                    progress: Callable[[str], None] | None = None) -> dict[str, Any]:
        """Verify device credentials over RPS, close the connection, return safe metadata.

        This does not start video or create an account session. Auth/transport
        failures raise CloudIdError; device rejection remains an explicit result.
        """
        if not isinstance(username, str) or not username.strip() or not isinstance(password, str):
            raise CloudIdError('input', 'invalid_device_credentials')

        def emit(stage: str) -> None:
            if progress:
                progress(stage)

        emit('auth_codes_request')
        codes = self.auth_codes(cloud_id)
        emit('status_request')
        status = self.discover_status(codes)
        out = {'authenticated': False, 'account_login_used': False, 'login_mode': 'password',
               'device_authentication': 'not_attempted', **status.safe_summary()}
        if status.status != 'Online':
            return {**out, 'stage': 'status', 'reason': 'device_offline'}

        def endpoint(host: Any, port: Any, stage: str) -> tuple[str, int]:
            try:
                address = str(ipaddress.ip_address(str(host or '').strip()))
                number = int(port)
                if not 1 <= number <= 65535:
                    raise ValueError('port')
                return address, number
            except (ValueError, TypeError):
                raise CloudIdError(stage, 'invalid_relay_address') from None

        server, port = endpoint(status.entry.get('ServerIP'), status.entry.get('ServerPort'), 'status')
        token, session = api.get_agent_client_uuid(), api.build_session_id()
        auth = codes.for_service('rps')
        selector = api.build_agent_protocol_payload(
            authcode=auth, serial_number=codes.serial_number, client_token=token,
            dest_port=str(status.entry.get('DevicePort') or '34567'), service_type='RpsCmd',
            session_id=session, encrypt='1', step='0', protocol_mode='tcp')
        emit('relay_selector_request')
        url_host = f'[{server}]' if ':' in server else server
        selected = api.agent_protocol_query(
            url=f'https://{url_host}:{port}/', payload=selector, timeout=self.timeout,
            ssl_verify=self.ssl_verify, runtime_mode='baseline_20260323')
        if not selected.ok:
            raise _transport_error('relay', selected)
        relay = api.parse_agent_protocol_response(selected.json_data)
        if str(relay.get('error_num')) != '200':
            raise CloudIdError('relay', 'server_rejected')
        host, port = endpoint(relay.get('agent_server_ip'), relay.get('agent_server_port'), 'relay')
        random_a = api._generate_ascii_key(32)

        def relay_progress(detail: str) -> None:
            # Forward fixed stage names only; raw transport messages may include
            # network addresses or server-provided fields.
            for prefix, stage in (
                ('TCP connect response', 'relay_connected'),
                ('TCP 6611 handshake request', 'relay_handshake_request'),
                ('TCP OPMonitor Claim request', 'claim_request'),
                ('TCP request sent cmd=0x03e8', 'device_login_sent'),
                ('TCP response cmd=0x03e9', 'device_login_response'),
            ):
                if detail.startswith(prefix):
                    emit(stage)
                    break

        emit('relay_connect_request')
        try:
            result = api.AgentTcpEncryptedClaimProbe().run_probe(
                host=host, port=port, authcode=auth, client_token=token,
                serial=codes.serial_number, session=session,
                xor_key=str(relay.get('random_str') or ''), claim_random_a=random_a,
                session_int=0x1869F, channel=int(channel), stream_type='Main',
                trans_mode='TCP', combine_mode='CONNECT_ALL', msg_id=0x10, unk=0x63,
                cmd=0x0585, timeout=self.timeout,
                capture_seconds=max(1, min(float(capture_seconds), 15)), max_frames=20,
                controller_auto=False,
                login_followup_builder={'mode': 'password', 'username': username,
                                        'password': password, 'random_a': random_a,
                                        'login_type': 'DVRIP-Web'},
                progress_callback=relay_progress)
        except OSError:
            raise CloudIdError('relay', 'transport_error') from None

        handshake_ok = bool((result.get('handshake') or {}).get('ok'))
        claim = result.get('claim') or {}
        sent = [f for f in claim.get('followups') or []
                if f.get('cmd') == 0x03E8 and not f.get('send_error')]
        replies = (result.get('frames') or {}).get('control_frames') or []
        expected_ids = {f.get('msg_id') for f in sent}
        matched = [api._frame_json_payload(f) for f in replies
                   if f.get('cmd') == 0x03E9 and f.get('msg_id') in expected_ids]
        ret = next((r['Ret'] for r in matched if type(r.get('Ret')) is int), None)
        success = handshake_ok and bool(sent) and ret == 100
        out.update(authenticated=success, login_ret=ret, relay_handshake_ok=handshake_ok,
                   login_request_sent=bool(sent), stage='login',
                   device_authentication=('success' if success else 'not_attempted' if not sent
                                          else 'rejected' if ret is not None else 'no_reply'))
        if not success:
            out['reason'] = {203: 'incorrect_password', 204: 'invalid_user',
                             205: 'user_locked', 206: 'user_blocked'}.get(ret, 'login_not_confirmed')
        return out
