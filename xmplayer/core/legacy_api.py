from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import select
import secrets
import socket
import ssl
import string
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Cipher import PKCS1_v1_5 as _PKCS1_v1_5
    from Crypto.PublicKey import RSA as _RSA
except Exception:  # noqa: BLE001
    _AES = None
    _PKCS1_v1_5 = None
    _RSA = None

from .legacy_parsers import extract_possible_stream_urls
from .agent_diagnostics import summarize_agent_response
from .legacy_signature import SignedHeadersInput, build_signed_headers, compute_signature
from .ptz import build_binary_ptz_followup


DEFAULT_BOSS_BASES = [
    "https://boss22-api-as.xmcsrv.net",
    "https://boss22-api-cn.xmcsrv.net",
    "https://boss-api-as.jftechsoft.com",
    "https://boss-api.jftechsoft.com",
]

DEFAULT_OPENAPI_BASES = [
    "https://api.jftechws.com",
]

DEFAULT_ACCESS_PMS_BASES = [
    "http://access-pms.secu100.net:6602",
    "https://access-pms.secu100.net:6502",
]
DEFAULT_IDR_STATUS_BASES = [
    "https://pub-status.secu100.net:7600/v1/status/third",
    "http://access-pms.secu100.net:6602",
    "https://access-pms.secu100.net:6502",
]
DEFAULT_WAKEUP_HOST = "access-pms.secu100.net"
DEFAULT_WAKEUP_PORT = 6602

DEFAULT_STATUS_BASE = "https://pub-status.secu100.net:7605/"
DEFAULT_STATUS_UA = "null-null-funsdk-v1.6.4b-Android"

LOGIN_PATH = "/account/userToken/login"
DEVICE_TOKEN_PATH = "/deviceToken/get"
JVSS_DEVICE_TOKEN_PATH = "/device/getDeviceTokenByTCS"
DEFAULT_JVSS_BASES = [
    "https://jvss.xmcsrv.net",
    "https://eu-jvss.xmcsrv.net",
    "https://af-jvss.xmcsrv.net",
]
DEFAULT_AMS_BASES = [
    "https://eu-ams.jftechws.com",
]
DEFAULT_AMS_USER_AGENT = "BQ-5056_Android_24_7321775314150220_iCSee_7.7.9_G_77930_v1.6.9"
MEDIA_PAYLOAD_B64_LIMIT = 1024
MEDIA_FRAME_SUMMARY_LIMIT = 1024


@dataclass
class HttpResult:
    ok: bool
    url: str
    status: int | None
    json_data: Any | None
    text: str
    error: str | None = None
    request_payload: Any | None = None

    def summary(self) -> str:
        code, _ = _extract_code_and_msg(self.json_data)
        return f"ok={self.ok} status={self.status} code={code} url={self.url}"


def _json_dumps(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _use_system_proxy() -> bool:
    return str(os.environ.get("XMPLAYER_USE_SYSTEM_PROXY") or "").strip().lower() in {"1", "true", "yes", "on"}


def _socks5_proxy_endpoint() -> tuple[str, int] | None:
    raw = str(os.environ.get("XMPLAYER_SOCKS5_PROXY") or os.environ.get("SOCKS5_PROXY") or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"socks5://{raw}"
    parsed = urllib.parse.urlparse(raw)
    host = str(parsed.hostname or "").strip()
    port = int(parsed.port or 0)
    if not host or port <= 0:
        return None
    return host, port


def _create_tcp_connection(address: tuple[str, int], timeout: int | float) -> socket.socket:
    proxy = _socks5_proxy_endpoint()
    if not proxy:
        return socket.create_connection(address, timeout=timeout)
    target_host, target_port = str(address[0]), int(address[1])
    sock = socket.create_connection(proxy, timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        reply = sock.recv(2)
        if reply != b"\x05\x00":
            raise OSError(f"socks5 auth failed: {reply.hex()}")
        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            raise OSError("socks5 target host is too long")
        request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack(">H", target_port)
        sock.sendall(request)
        head = sock.recv(4)
        if len(head) != 4 or head[0] != 5 or head[1] != 0:
            raise OSError(f"socks5 connect failed: {head.hex()}")
        atyp = head[3]
        if atyp == 1:
            to_read = 4
        elif atyp == 3:
            length = sock.recv(1)
            if len(length) != 1:
                raise OSError("socks5 truncated domain reply")
            to_read = int(length[0])
        elif atyp == 4:
            to_read = 16
        else:
            raise OSError(f"socks5 unknown atyp: {atyp}")
        remaining = to_read + 2
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise OSError("socks5 truncated connect reply")
            remaining -= len(chunk)
        return sock
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def _urlopen_direct(req: urllib.request.Request, *, timeout: int | float, context: ssl.SSLContext):
    if _use_system_proxy():
        return urllib.request.urlopen(req, timeout=timeout, context=context)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    return opener.open(req, timeout=timeout)


def http_json(
    url: str,
    method: str = "POST",
    payload: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
    ssl_verify: bool = True,
) -> HttpResult:
    data = _json_dumps(payload) if payload is not None else None
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url=url, data=data, headers=req_headers, method=method.upper())
    context = ssl.create_default_context()
    if not ssl_verify:
        context = ssl._create_unverified_context()  # noqa: SLF001
    if _socks5_proxy_endpoint():
        raw_result = http_minimal_text(
            url=url,
            method=method,
            payload=data,
            headers=req_headers,
            timeout=timeout,
            ssl_verify=ssl_verify,
        )
        try:
            json_data = json.loads(raw_result.text)
        except Exception:
            json_data = None
        return HttpResult(
            ok=raw_result.ok,
            url=url,
            status=raw_result.status,
            json_data=json_data,
            text=raw_result.text,
            error=raw_result.error,
            request_payload=payload,
        )
    try:
        with _urlopen_direct(req, timeout=timeout, context=context) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                json_data = json.loads(raw)
            except Exception:
                json_data = None
            return HttpResult(
                ok=True,
                url=url,
                status=resp.getcode(),
                json_data=json_data,
                text=raw,
                request_payload=payload,
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            json_data = json.loads(raw)
        except Exception:
            json_data = None
        return HttpResult(
            ok=False,
            url=url,
            status=exc.code,
            json_data=json_data,
            text=raw,
            error=str(exc),
            request_payload=payload,
        )
    except Exception as exc:
        return HttpResult(
            ok=False,
            url=url,
            status=None,
            json_data=None,
            text="",
            error=str(exc),
            request_payload=payload,
        )


def http_text(
    url: str,
    method: str = "POST",
    payload: bytes | str | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
    ssl_verify: bool = True,
) -> HttpResult:
    data: bytes | None
    if isinstance(payload, str):
        data = payload.encode("utf-8")
    else:
        data = payload
    req_headers = dict(headers or {})
    req = urllib.request.Request(url=url, data=data, headers=req_headers, method=method.upper())
    context = ssl.create_default_context()
    if not ssl_verify:
        context = ssl._create_unverified_context()  # noqa: SLF001
    if _socks5_proxy_endpoint():
        return http_minimal_text(
            url=url,
            method=method,
            payload=data,
            headers=req_headers,
            timeout=timeout,
            ssl_verify=ssl_verify,
        )
    try:
        with _urlopen_direct(req, timeout=timeout, context=context) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return HttpResult(
                ok=True,
                url=url,
                status=resp.getcode(),
                json_data=None,
                text=raw,
                request_payload=payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload,
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return HttpResult(
            ok=False,
            url=url,
            status=exc.code,
            json_data=None,
            text=raw,
            error=str(exc),
            request_payload=payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload,
        )
    except Exception as exc:
        return HttpResult(
            ok=False,
            url=url,
            status=None,
            json_data=None,
            text="",
            error=str(exc),
            request_payload=payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload,
        )


def http_minimal_text(
    url: str,
    method: str = "POST",
    payload: bytes | str | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
    ssl_verify: bool = True,
) -> HttpResult:
    def _chunked_body_complete(data: bytes) -> bool:
        body = data
        pos = 0
        total = len(body)
        while True:
            line_end = body.find(b"\r\n", pos)
            if line_end < 0:
                return False
            line = body[pos:line_end].split(b";", 1)[0].strip()
            try:
                size = int(line.decode("ascii", errors="ignore") or "0", 16)
            except Exception:
                return False
            pos = line_end + 2
            if total < pos + size + 2:
                return False
            if size == 0:
                return total >= pos + 2
            pos += size
            if body[pos:pos + 2] != b"\r\n":
                return False
            pos += 2

    parsed = urllib.parse.urlparse(url)
    host = str(parsed.hostname or "").strip()
    if not host:
        return HttpResult(ok=False, url=url, status=None, json_data=None, text="", error="missing_host")
    scheme = (parsed.scheme or "https").lower()
    port = int(parsed.port or (443 if scheme == "https" else 80))
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    if isinstance(payload, str):
        body = payload.encode("utf-8")
        request_payload = payload
    else:
        body = payload or b""
        request_payload = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body

    host_header = parsed.netloc or host
    header_lines = [
        f"{method.upper()} {path} HTTP/1.1",
        f"Host: {host_header}",
        "Connection: close",
        f"Content-Length: {len(body)}",
    ]
    for name, value in dict(headers or {}).items():
        name_s = str(name).strip()
        if not name_s or name_s.lower() in {"host", "connection", "content-length"}:
            continue
        header_lines.append(f"{name_s}: {value}")
    request = ("\r\n".join(header_lines) + "\r\n\r\n").encode("iso-8859-1") + body

    sock: socket.socket | None = None
    wrapped: ssl.SSLSocket | socket.socket | None = None
    try:
        sock = _create_tcp_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if scheme == "https":
            context = ssl.create_default_context()
            if not ssl_verify:
                context = ssl._create_unverified_context()  # noqa: SLF001
            wrapped = context.wrap_socket(sock, server_hostname=host)
        else:
            wrapped = sock
        assert wrapped is not None
        wrapped.sendall(request)
        chunks: list[bytes] = []
        header_end = -1
        expected_body_len: int | None = None
        chunked = False
        while True:
            try:
                chunk = wrapped.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            raw = b"".join(chunks)
            if header_end < 0:
                header_end = raw.find(b"\r\n\r\n")
                if header_end >= 0:
                    header_bytes = raw[:header_end]
                    header_text = header_bytes.decode("iso-8859-1", errors="replace")
                    for line in header_text.split("\r\n")[1:]:
                        name, sep, value = line.partition(":")
                        if not sep:
                            continue
                        name_l = name.strip().lower()
                        value_s = value.strip()
                        if name_l == "content-length":
                            try:
                                expected_body_len = int(value_s)
                            except Exception:
                                expected_body_len = None
                        elif name_l == "transfer-encoding" and "chunked" in value_s.lower():
                            chunked = True
            if header_end >= 0:
                body = raw[header_end + 4 :]
                if expected_body_len is not None and len(body) >= expected_body_len:
                    break
                if chunked and _chunked_body_complete(body):
                    break
        raw = b"".join(chunks)
        header_part, _, body_part = raw.partition(b"\r\n\r\n")
        header_text = header_part.decode("iso-8859-1", errors="replace")
        body_text = body_part.decode("utf-8", errors="replace")
        status = None
        first_line = header_text.splitlines()[0] if header_text else ""
        if first_line.startswith("HTTP/"):
            parts = first_line.split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        return HttpResult(
            ok=status is not None and 200 <= status < 300,
            url=url,
            status=status,
            json_data=None,
            text=body_text,
            request_payload=request_payload,
        )
    except Exception as exc:
        return HttpResult(
            ok=False,
            url=url,
            status=None,
            json_data=None,
            text="",
            error=str(exc),
            request_payload=request_payload,
        )
    finally:
        try:
            if wrapped is not None:
                wrapped.close()
        except Exception:
            pass
        if sock is not None and wrapped is not sock:
            try:
                sock.close()
            except Exception:
                pass


def build_agent_protocol_payload(
    *,
    authcode: str,
    serial_number: str,
    client_token: str,
    dest_port: str,
    service_type: str,
    session_id: str,
    encrypt: str,
    step: str,
    protocol_mode: str = "",
    vendor: str = "",
) -> dict[str, Any]:
    body = {
        "Authcode": authcode,
        "ClientToken": client_token,
        "DestPort": dest_port,
        "Encrypt": encrypt,
        "ProtocolMode": protocol_mode,
        "SerialNumber": serial_number,
        "ServiceType": service_type,
        "SessionId": session_id,
        "Step": step,
    }
    if not protocol_mode:
        body.pop("ProtocolMode", None)
    normalized_vendor = str(vendor or "").strip()
    if normalized_vendor and normalized_vendor.lower() != "general":
        body["Vendor"] = vendor
    header = {
        "Version": "1.0",
        "MessageType": "MSG_CLI_NEED_CON_REQ",
    }
    return {"AgentProtocol": {"Body": body, "Header": header}}


def build_status_protocol_payload(
    serial_number: str,
    authcode: str,
    *,
    manufacturer: str = "",
    message_type: str = "MSG_STATUS_LOCALQUERY_REQ",
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "SerialNumber": serial_number,
        "AuthCode": authcode,
    }
    if str(manufacturer or "").strip():
        body["Manufacturer"] = str(manufacturer or "").strip()
    return {
        "StatusProtocol": {
            "Header": {"Version": "1.0", "CSeq": "1", "MessageType": str(message_type or "MSG_STATUS_LOCALQUERY_REQ")},
            "Body": [body],
        }
    }


def parse_status_protocol_response(json_data: Any) -> dict[str, Any]:
    if not isinstance(json_data, dict):
        return {}
    proto = json_data.get("StatusProtocol") if isinstance(json_data.get("StatusProtocol"), dict) else {}
    header = proto.get("Header") if isinstance(proto.get("Header"), dict) else {}
    body = proto.get("Body") if isinstance(proto.get("Body"), list) else []
    return {
        "message_type": header.get("MessageType"),
        "error_num": header.get("ErrorNum"),
        "error_string": header.get("ErrorString"),
        "body": body,
    }


def parse_alarm_center_response(json_data: Any) -> dict[str, Any]:
    if not isinstance(json_data, dict):
        return {}
    proto = json_data.get("AlarmCenter") if isinstance(json_data.get("AlarmCenter"), dict) else {}
    header = proto.get("Header") if isinstance(proto.get("Header"), dict) else {}
    body = proto.get("Body")
    return {
        "message_type": header.get("MessageType"),
        "error_num": header.get("ErrorNum"),
        "error_string": header.get("ErrorString"),
        "body": body,
    }


def normalize_idr_status_entry(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    conn = entry.get("conn_params") if isinstance(entry.get("conn_params"), dict) else {}
    normalized = dict(entry)
    if conn:
        if not normalized.get("ServerIP") and conn.get("ServerIP"):
            normalized["ServerIP"] = conn.get("ServerIP")
        if not normalized.get("ServerPort") and conn.get("ServerPort") is not None:
            normalized["ServerPort"] = conn.get("ServerPort")
        if not normalized.get("NatType") and conn.get("NatType") is not None:
            normalized["NatType"] = conn.get("NatType")
        if not normalized.get("DevInfo") and conn.get("DevInfo") is not None:
            normalized["DevInfo"] = conn.get("DevInfo")
        if normalized.get("DevStatus") is None and conn.get("DevStatus") is not None:
            normalized["DevStatus"] = conn.get("DevStatus")
        if normalized.get("WakeUpEnable") is None and conn.get("WakeUpEnable") is not None:
            normalized["WakeUpEnable"] = conn.get("WakeUpEnable")
    if not normalized.get("Status") and entry.get("status"):
        normalized["Status"] = entry.get("status")
    return normalized


def status_protocol_query(
    *,
    serial_number: str,
    authcode: str,
    base: str = DEFAULT_STATUS_BASE,
    timeout: int = 15,
    ssl_verify: bool = False,
    user_agent: str = DEFAULT_STATUS_UA,
    content_type: str = "text/html",
    manufacturer: str = "",
    message_type: str = "MSG_STATUS_LOCALQUERY_REQ",
) -> HttpResult:
    payload = build_status_protocol_payload(
        serial_number=serial_number,
        authcode=authcode,
        manufacturer=manufacturer,
        message_type=message_type,
    )
    headers = {
        "Accept": "*/*",
        "User-Agent": user_agent,
        "Content-Type": content_type,
    }
    return http_json(url=base, method="POST", payload=payload, headers=headers, timeout=timeout, ssl_verify=ssl_verify)


def agent_protocol_query(
    *,
    url: str,
    payload: dict[str, Any],
    timeout: int = 15,
    ssl_verify: bool = False,
    user_agent: str = DEFAULT_STATUS_UA,
    content_type: str = "text/html",
    runtime_mode: str = "experimental_current",
) -> HttpResult:
    normalized_runtime_mode = str(runtime_mode or "experimental_current").strip() or "experimental_current"
    if normalized_runtime_mode == "baseline_20260323":
        headers = {
            "Accept": "*/*",
            "User-Agent": user_agent,
            "Content-Type": content_type,
        }
        return http_json(
            url=url,
            method="POST",
            payload=payload,
            headers=headers,
            timeout=timeout,
            ssl_verify=ssl_verify,
        )
    raw_payload = _json_dumps(payload)
    result = http_minimal_text(
        url=url,
        method="POST",
        payload=raw_payload,
        timeout=timeout,
        ssl_verify=ssl_verify,
    )
    if result.text:
        try:
            result.json_data = json.loads(result.text)
        except Exception:
            result.json_data = None
    return result


def build_agent_payload_variants(
    *,
    authcode: str,
    serial_number: str,
    client_token: str,
    dest_port: str,
    service_type: str,
    session_id: str,
    encrypt: str,
    step: str,
    protocol_mode: str = "",
    vendor: str = "",
) -> list[dict[str, Any]]:
    service_types = [service_type]
    if service_type and service_type.upper() != service_type:
        service_types.append(service_type.upper())
    if service_type and service_type.lower() != service_type:
        service_types.append(service_type.lower())
    service_types = _dedupe([s for s in service_types if s])
    payloads: list[dict[str, Any]] = []
    for stype in service_types or [service_type]:
        payloads.append(
            build_agent_protocol_payload(
                authcode=authcode,
                serial_number=serial_number,
                client_token=client_token,
                dest_port=dest_port,
                service_type=stype,
                session_id=session_id,
                encrypt=encrypt,
                step=step,
                protocol_mode=protocol_mode,
                vendor=vendor,
            )
        )
    return payloads


def parse_agent_protocol_response(json_data: Any) -> dict[str, Any]:
    if not isinstance(json_data, dict):
        return {}
    agent = json_data.get("AgentProtocol") if isinstance(json_data.get("AgentProtocol"), dict) else {}
    header = agent.get("Header") if isinstance(agent.get("Header"), dict) else {}
    body = agent.get("Body") if isinstance(agent.get("Body"), dict) else {}
    return {
        "message_type": header.get("MessageType"),
        "error_num": header.get("ErrorNum"),
        "error_string": header.get("ErrorString"),
        "agent_server_ip": body.get("AgentServerIp"),
        "agent_server_port": body.get("AgentServerPort"),
        "agent_server_lan_ip": body.get("AgentServerLanIp"),
        "agent_server_dns": body.get("AgentServerDNS"),
        "random_str": body.get("RandomStr"),
        "protocol_mode": body.get("ProtocolMode"),
    }


def select_agent_server_via_query(
    *,
    authcode: str,
    serial: str,
    client_token: str,
    dest_port: str,
    service_type: str,
    session_id: str,
    encrypt: str,
    step: str,
    protocol_mode: str,
    vendor: str,
    access_urls: list[str],
    content_types: list[str],
    timeout: int,
    ssl_verify: bool,
    user_agent: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    selected: dict[str, Any] = {}
    agent_server: dict[str, Any] = {}
    payloads = build_agent_payload_variants(
        authcode=authcode,
        serial_number=serial,
        client_token=client_token,
        dest_port=dest_port,
        service_type=service_type,
        session_id=session_id,
        encrypt=encrypt,
        step=step,
        protocol_mode=protocol_mode,
        vendor=vendor,
    )
    for payload in payloads:
        payload_body = payload.get("AgentProtocol", {}).get("Body", {})
        for agent_url in access_urls:
            for content_type in content_types:
                response = agent_protocol_query(
                    url=agent_url,
                    payload=payload,
                    timeout=max(1, int(timeout)),
                    ssl_verify=ssl_verify if agent_url.startswith("https://") else False,
                    user_agent=user_agent,
                    content_type=content_type,
                )
                parsed = parse_agent_protocol_response(response.json_data)
                attempt = {
                    "ok": response.ok,
                    "status": response.status,
                    "url": response.url,
                    "content_type": content_type,
                    "service_type": payload_body.get("ServiceType"),
                    "step": payload_body.get("Step"),
                    "parsed": parsed,
                    "response_diagnostics": summarize_agent_response(
                        response.json_data, request_payload=payload, transport_error=response.error,
                    ),
                    "response_head": (response.text or "")[:400],
                    "error": response.error,
                }
                attempts.append(attempt)
                if parsed.get("agent_server_ip") and parsed.get("agent_server_port"):
                    selected = dict(attempt)
                    agent_server = {
                        "ip": str(parsed.get("agent_server_ip") or ""),
                        "port": int(parsed.get("agent_server_port") or 0),
                        "random_str": str(parsed.get("random_str") or ""),
                        "protocol_mode": str(parsed.get("protocol_mode") or ""),
                    }
                    return attempts, selected, agent_server
    return attempts, selected, agent_server


class AccessServerProbe:
    def __init__(self, bases: list[str] | None = None) -> None:
        self.bases = bases or list(DEFAULT_ACCESS_PMS_BASES)

    def probe_agent_protocol(
        self,
        payloads: list[dict[str, Any]],
        timeout: int = 20,
        ssl_verify: bool = True,
    ) -> list[HttpResult]:
        results: list[HttpResult] = []
        for base in self.bases:
            url = f"{base.rstrip('/')}/"
            for payload in payloads:
                results.append(
                    http_json(
                        url=url,
                        method="POST",
                        payload=payload,
                        timeout=timeout,
                        ssl_verify=ssl_verify,
                    )
                )
        return results


_NATIVE_AGENT_ALPHABET = string.digits + string.ascii_lowercase
_AGENT_CLIENT_UUID_FILENAME = "agent_client_uuid.txt"


def build_client_token(prefix: str = "c_", length: int = 24) -> str:
    alphabet = _NATIVE_AGENT_ALPHABET
    return prefix + "".join(secrets.choice(alphabet) for _ in range(length))


def build_session_id(length: int = 32) -> str:
    alphabet = _NATIVE_AGENT_ALPHABET
    return "".join(secrets.choice(alphabet) for _ in range(length))


_AGENT_CLIENT_UUID_LOCK = threading.Lock()
_AGENT_CLIENT_UUID = ""
_AMS_TIME_COUNTER_LOCK = threading.Lock()
_AMS_TIME_COUNTER = 0


def _agent_client_uuid_path() -> Path:
    root = Path(__file__).resolve().parents[1]
    return root / "config" / _AGENT_CLIENT_UUID_FILENAME


def _agent_client_machine_id() -> str:
    name = str(os.environ.get("COMPUTERNAME") or socket.gethostname() or "").strip().lower()
    user = str(os.environ.get("USERNAME") or os.environ.get("USER") or "").strip().lower()
    return f"{name}/{user}" if user else name


def _is_valid_agent_client_uuid(value: str) -> bool:
    raw = str(value or "").strip()
    if len(raw) != 26 or not raw.startswith("c_"):
        return False
    return all(ch in _NATIVE_AGENT_ALPHABET for ch in raw[2:])


def _load_agent_client_uuid_cache(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8-sig").strip()
    except Exception:
        return ""
    if not text:
        return ""
    try:
        payload = json.loads(text)
    except Exception:
        return text if _is_valid_agent_client_uuid(text) else ""
    if not isinstance(payload, dict):
        return ""
    token = str(payload.get("client_token") or "").strip()
    if not _is_valid_agent_client_uuid(token):
        return ""
    if str(payload.get("machine_id") or "").strip().lower() == _agent_client_machine_id():
        return token
    return ""


def _save_agent_client_uuid_cache(path: Path, token: str) -> None:
    payload = {
        "version": 1,
        "portable": False,
        "machine_id": _agent_client_machine_id(),
        "client_token": token,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _set_agent_client_uuid(token: str) -> None:
    global _AGENT_CLIENT_UUID
    if not _is_valid_agent_client_uuid(token):
        return
    with _AGENT_CLIENT_UUID_LOCK:
        _AGENT_CLIENT_UUID = token
        try:
            _save_agent_client_uuid_cache(_agent_client_uuid_path(), token)
        except Exception:
            pass


def get_agent_client_uuid() -> str:
    global _AGENT_CLIENT_UUID
    with _AGENT_CLIENT_UUID_LOCK:
        if _AGENT_CLIENT_UUID and _is_valid_agent_client_uuid(_AGENT_CLIENT_UUID):
            return _AGENT_CLIENT_UUID
        cache_path = _agent_client_uuid_path()
        cached = _load_agent_client_uuid_cache(cache_path)
        if _is_valid_agent_client_uuid(cached):
            _AGENT_CLIENT_UUID = cached
            return _AGENT_CLIENT_UUID
        _AGENT_CLIENT_UUID = build_client_token()
        try:
            _save_agent_client_uuid_cache(cache_path, _AGENT_CLIENT_UUID)
        except Exception:
            pass
        return _AGENT_CLIENT_UUID


def _next_ams_time_millis(now_ms: int | None = None) -> str:
    global _AMS_TIME_COUNTER
    with _AMS_TIME_COUNTER_LOCK:
        _AMS_TIME_COUNTER += 1
        if _AMS_TIME_COUNTER > 9_999_999:
            _AMS_TIME_COUNTER = 1
        counter = _AMS_TIME_COUNTER
    millis = int(now_ms if now_ms is not None else time.time() * 1000)
    return f"{counter:07d}{millis}"


def _derive_ams_response_key(time_millis: str, secret: str) -> str:
    raw_time = str(time_millis or "").strip()
    raw_secret = str(secret or "").strip()
    base = raw_time[len(raw_time) // 2 :] + raw_secret
    if len(base) < 16:
        base += "".join(str(idx) for idx in range(16 - len(base)))
    return base[:16]


def _strip_pkcs7_padding(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if pad <= 0 or pad > 16:
        return data.rstrip(b"\x00")
    tail = data[-pad:]
    if tail != bytes([pad]) * pad:
        return data.rstrip(b"\x00")
    return data[:-pad]


def _pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad = block_size - (len(data) % block_size)
    if pad <= 0:
        pad = block_size
    return data + bytes([pad]) * pad


def _decrypt_ams_hex_payload(hex_text: str, aes_key: str) -> str:
    if _AES is None:
        raise RuntimeError("pycryptodome is required for AMS AES decrypt")
    raw_hex = "".join(str(hex_text or "").split())
    if not raw_hex:
        return ""
    cipher = _AES.new(str(aes_key or "").encode("utf-8"), _AES.MODE_ECB)
    plain = cipher.decrypt(bytes.fromhex(raw_hex))
    plain = _strip_pkcs7_padding(plain)
    return plain.decode("utf-8", errors="replace")


def _encrypt_ams_hex_payload(plain_text: str, aes_key: str) -> str:
    if _AES is None:
        raise RuntimeError("pycryptodome is required for AMS AES encrypt")
    plain_bytes = _pad_pkcs7(str(plain_text or "").encode("utf-8"))
    cipher = _AES.new(str(aes_key or "").encode("utf-8"), _AES.MODE_ECB)
    return cipher.encrypt(plain_bytes).hex().upper()


def _extract_ams_devices(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    devices: list[dict[str, Any]] = []
    for group in ("mine", "share"):
        rows = data.get(group)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            item = dict(row)
            item["_group"] = group
            item["_device_id"] = str(
                row.get("uuid") or row.get("sn") or row.get("devSn") or row.get("deviceId") or ""
            ).strip()
            devices.append(item)
    return devices


def _extract_acapp_auth_rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    rows: list[dict[str, Any]] = []
    data = payload.get("data")
    candidates: list[Any] = []
    if isinstance(data, list):
        candidates.extend(data)
    elif isinstance(data, dict):
        candidates.append(data)
        for value in data.values():
            if isinstance(value, list):
                candidates.extend(value)
            elif isinstance(value, dict):
                candidates.append(value)
    elif isinstance(payload.get("result"), list):
        candidates.extend(payload.get("result"))
    for row in candidates:
        if not isinstance(row, dict):
            continue
        auth_name = str(
            row.get("type")
            or row.get("authname")
            or row.get("authName")
            or row.get("auth_type")
            or row.get("name")
            or ""
        ).strip()
        auth_code = str(
            row.get("auth")
            or row.get("authcode")
            or row.get("authCode")
            or row.get("value")
            or row.get("code")
            or ""
        ).strip()
        device_id = str(
            row.get("uuid")
            or row.get("sn")
            or row.get("serial")
            or row.get("serialNumber")
            or row.get("deviceId")
            or row.get("devId")
            or ""
        ).strip()
        if not auth_name and not auth_code and not device_id:
            continue
        normalized = dict(row)
        normalized["_device_id"] = device_id
        normalized["_auth_name"] = auth_name
        normalized["_auth_code"] = auth_code
        rows.append(normalized)
    return rows


TCP_MAGIC = b"\xFF\x01"
TCP_HEADER_LEN = 20
TCP_HANDSHAKE_SUFFIX = b"]q\x04"
TCP_BASE64_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
SPECIAL_LOGIN_AES_KEY = b"dashoiahfarqdasr"
WAKEUP_SUFFIX = b"XXEE"


def _format_handshake_wire_text(text: str, suffix: bytes) -> str:
    raw = str(text or "").encode("utf-8") + bytes(suffix or b"")
    return raw.decode("utf-8", errors="backslashreplace")


@dataclass
class TcpFrame:
    msg_type: int
    session_id: int
    msg_id: int
    unk: int
    cmd: int
    code_le: int
    code_be: int
    payload: bytes

    def summary(self) -> dict[str, Any]:
        return {
            "msg_type": self.msg_type,
            "session_id": self.session_id,
            "msg_id": self.msg_id,
            "unk": self.unk,
            "cmd": self.cmd,
            "code_le": self.code_le,
            "code_be": self.code_be,
            "payload_len": len(self.payload),
        }


def _is_base64_byte(value: int) -> bool:
    return value in TCP_BASE64_BYTES


def _split_base64_prefix(data: bytes) -> tuple[bytes, bytes]:
    idx = 0
    while idx < len(data) and _is_base64_byte(data[idx]):
        idx += 1
    return data[:idx], data[idx:]


def _decode_base64_with_suffix(raw_b64: bytes, suffix: bytes) -> tuple[bytes | None, str]:
    if not raw_b64:
        return None, "b64_length"
    candidates = [raw_b64]
    # 6611 handshake replies are base64 JSON followed by the literal wire
    # terminator XXEE. Python 3.14.5 is stricter about this trailing text than
    # older builds, so strip it before decoding when present.
    if raw_b64.endswith(WAKEUP_SUFFIX):
        candidates.insert(0, raw_b64[: -len(WAKEUP_SUFFIX)])
    decoded = None
    last_error = ""
    for candidate in candidates:
        if not candidate or len(candidate) % 4 != 0:
            last_error = "b64_length"
            continue
        try:
            decoded = base64.b64decode(candidate)
            break
        except Exception as exc:  # noqa: BLE001
            last_error = f"b64_decode:{exc}"
    if decoded is None:
        return None, last_error or "b64_decode"
    if not decoded.endswith(suffix):
        # Some first-6611 handshake replies decode to plain JSON without the
        # client-side ]q\\x04 suffix even though they are still valid base64
        # messages on the wire (for example eyJ...XXEE -> {"ErrorNum":...}).
        trimmed = decoded.strip()
        if trimmed[:1] in (b"{", b"[") and trimmed[-1:] in (b"}", b"]"):
            return decoded, ""
        return None, "b64_suffix"
    return decoded, ""


def _recv_base64_message(
    sock: socket.socket,
    timeout: float,
    suffix: bytes,
    max_bytes: int = 4096,
) -> tuple[bytes, bytes, str]:
    deadline = time.time() + timeout
    buffer = b""
    while time.time() < deadline:
        sock.settimeout(max(0.1, min(1.0, deadline - time.time())))
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            continue
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > max_bytes:
            break
        b64_prefix, remainder = _split_base64_prefix(buffer)
        if len(b64_prefix) < 4:
            continue
        decoded, err = _decode_base64_with_suffix(b64_prefix, suffix)
        if decoded is not None:
            return b64_prefix, remainder, ""
        if remainder:
            return b64_prefix, remainder, err
    return b"", buffer, "timeout"


def _summarize_handshake_reply(b64_resp: bytes, parsed: dict[str, Any]) -> dict[str, Any]:
    response_b64 = b64_resp.decode("ascii", errors="ignore")
    json_data = parsed.get("json") if isinstance(parsed, dict) else None
    dest_ip = str(json_data.get("DestIP") or "") if isinstance(json_data, dict) else ""
    return {
        "response_b64": response_b64,
        "response_text": str(parsed.get("text") or "") if isinstance(parsed, dict) else "",
        "dest_ip": dest_ip,
        "is_dest_ip_reply": bool(dest_ip),
    }


def _build_tcp_frame(
    *,
    msg_type: int,
    session_id: int,
    msg_id: int,
    code: int,
    payload: bytes,
    code_endian: str = "be",
    unk: int | None = None,
    cmd: int | None = None,
) -> bytes:
    header = bytearray()
    header += TCP_MAGIC
    header += struct.pack("<H", msg_type & 0xFFFF)
    header += struct.pack("<I", session_id & 0xFFFFFFFF)
    header += struct.pack("<I", msg_id & 0xFFFFFFFF)
    if unk is not None or cmd is not None:
        header += struct.pack("<H", int(unk or 0) & 0xFFFF)
        header += struct.pack("<H", int(cmd or 0) & 0xFFFF)
    elif code_endian == "le":
        header += struct.pack("<I", code & 0xFFFFFFFF)
    else:
        header += struct.pack(">I", code & 0xFFFFFFFF)
    header += struct.pack("<I", len(payload))
    return bytes(header) + payload


def _parse_tcp_frames(buffer: bytes) -> tuple[list[TcpFrame], bytes]:
    frames: list[TcpFrame] = []
    offset = 0
    while len(buffer) - offset >= TCP_HEADER_LEN:
        if buffer[offset : offset + 2] != TCP_MAGIC:
            next_idx = buffer.find(TCP_MAGIC, offset + 1)
            if next_idx == -1:
                return frames, buffer[offset + 1 :]
            offset = next_idx
            if len(buffer) - offset < TCP_HEADER_LEN:
                break
        header = buffer[offset : offset + TCP_HEADER_LEN]
        msg_type = struct.unpack("<H", header[2:4])[0]
        session_id = struct.unpack("<I", header[4:8])[0]
        msg_id = struct.unpack("<I", header[8:12])[0]
        unk = struct.unpack("<H", header[12:14])[0]
        cmd = struct.unpack("<H", header[14:16])[0]
        code_le = struct.unpack("<I", header[12:16])[0]
        code_be = struct.unpack(">I", header[12:16])[0]
        payload_len = struct.unpack("<I", header[16:20])[0]
        frame_len = TCP_HEADER_LEN + payload_len
        if len(buffer) - offset < frame_len:
            break
        payload = buffer[offset + TCP_HEADER_LEN : offset + frame_len]
        frames.append(
            TcpFrame(
                msg_type=msg_type,
                session_id=session_id,
                msg_id=msg_id,
                unk=unk,
                cmd=cmd,
                code_le=code_le,
                code_be=code_be,
                payload=payload,
            )
        )
        offset += frame_len
    return frames, buffer[offset:]


def _format_session_hex(session_int: int, width: int = 10) -> str:
    return f"0x{session_int:0{width}x}"


class _XorKeystream:
    def __init__(self, key: str | bytes) -> None:
        if isinstance(key, str):
            key = key.encode("utf-8", errors="ignore")
        if not key:
            raise ValueError("xor key must not be empty")
        self.key = key
        self.offset = 0

    def apply(self, data: bytes) -> bytes:
        if not data:
            return b""
        out = bytearray(len(data))
        key = self.key
        key_len = len(key)
        start = self.offset
        for idx, value in enumerate(data):
            out[idx] = value ^ key[(start + idx) % key_len]
        self.offset += len(data)
        return bytes(out)


def _summarize_tcp_frame_payload(payload: bytes) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "payload_head_hex": payload[:64].hex(),
    }
    trimmed = payload.rstrip(b"\x00")
    text = trimmed.decode("utf-8", errors="ignore")
    if text:
        summary["payload_text"] = text
        raw_b64 = text.encode("ascii", errors="ignore")
        if raw_b64 and len(raw_b64) % 4 == 0:
            try:
                decoded = base64.b64decode(raw_b64)
            except Exception:  # noqa: BLE001
                decoded = b""
            if decoded:
                summary["payload_base64_len"] = len(decoded)
                summary["payload_base64_head_hex"] = decoded[:32].hex()
    return summary


def _decrypt_special_login_payload(frame: TcpFrame, summary: dict[str, Any]) -> None:
    if frame.cmd not in (0x586, 0x3E9):
        return
    if frame.session_id != 1099999:
        return
    if _AES is None:
        summary["aes_decrypt_error"] = "pycryptodome_unavailable"
        return
    payload_text = summary.get("payload_text")
    if not isinstance(payload_text, str) or not payload_text:
        return
    try:
        ciphertext = base64.b64decode(payload_text.encode("ascii"))
    except Exception as exc:  # noqa: BLE001
        summary["aes_decrypt_error"] = f"b64:{exc}"
        return
    if not ciphertext or len(ciphertext) % 16 != 0:
        summary["aes_decrypt_error"] = "ciphertext_len"
        return
    try:
        plaintext = _AES.new(SPECIAL_LOGIN_AES_KEY, _AES.MODE_CBC, iv=b"\x00" * 16).decrypt(ciphertext)
    except Exception as exc:  # noqa: BLE001
        summary["aes_decrypt_error"] = f"aes:{exc}"
        return
    plaintext = plaintext.rstrip(b"\x00")
    summary["aes_decrypted_len"] = len(plaintext)
    summary["aes_decrypted_head_hex"] = plaintext[:64].hex()
    try:
        text = plaintext.decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        summary["aes_decrypt_error"] = f"utf8:{exc}"
        return
    summary["aes_decrypted_text"] = text
    try:
        summary["aes_decrypted_json"] = json.loads(text)
    except Exception:
        pass


def _aes_cbc_zero_pad_decrypt_base64(raw_text: str, key_text: str) -> bytes:
    if _AES is None:
        return b""
    key_bytes = (key_text or "").encode("utf-8", errors="ignore")
    if len(key_bytes) not in (16, 24, 32):
        return b""
    try:
        ciphertext = base64.b64decode(str(raw_text or "").strip().encode("ascii"))
    except Exception:
        return b""
    if not ciphertext or (len(ciphertext) % 16) != 0:
        return b""
    try:
        plain = _AES.new(key_bytes, _AES.MODE_CBC, iv=b"\x00" * 16).decrypt(ciphertext)
    except Exception:
        return b""
    return plain.rstrip(b"\x00")


def _decrypt_dataenc_payload(
    frame: TcpFrame,
    summary: dict[str, Any],
    *,
    key_text: str,
    not_encrypt_cmds: set[int] | None = None,
) -> None:
    if not key_text:
        return
    if frame.cmd in (0x586, 0x03E9):
        return
    if not_encrypt_cmds and frame.cmd in not_encrypt_cmds:
        return
    payload_text = summary.get("payload_text")
    if not isinstance(payload_text, str) or not payload_text:
        return
    plain = _aes_cbc_zero_pad_decrypt_base64(payload_text, key_text)
    if not plain:
        return
    summary["dataenc_decrypted_len"] = len(plain)
    summary["dataenc_decrypted_head_hex"] = plain[:64].hex()
    try:
        text = plain.decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        summary["dataenc_decrypt_error"] = f"utf8:{exc}"
        return
    summary["dataenc_decrypted_text"] = text
    try:
        summary["dataenc_decrypted_json"] = json.loads(text)
    except Exception:
        pass


def _summarize_tcp_frame(
    frame: TcpFrame,
    *,
    dataenc_key: str = "",
    not_encrypt_cmds: Iterable[int] | None = None,
    include_payload_b64: bool = False,
) -> dict[str, Any]:
    summary = frame.summary()
    summary.update(_summarize_tcp_frame_payload(frame.payload))
    if include_payload_b64 and frame.payload:
        summary["payload_b64"] = base64.b64encode(frame.payload).decode("ascii")
    _decrypt_special_login_payload(frame, summary)
    _decrypt_dataenc_payload(
        frame,
        summary,
        key_text=dataenc_key,
        not_encrypt_cmds=set(not_encrypt_cmds or []),
    )
    return summary


def _build_stream_decrypt_key(random_str: str) -> bytes:
    text = str(random_str or "")
    if not text:
        return b""
    # Mirrors GetDecryptKey usage observed in CSTDStream::UpdateDataDecryptKey.
    if len(text) < 0x10:
        return b""
    raw = text.encode("utf-8", errors="ignore")
    fill = raw[:1] or b"\x00"
    padded = bytearray(fill * 0x24)
    padded[: min(len(raw), 0x24)] = raw[:0x24]
    key = bytearray(0x80)
    for idx in range(8):
        chunk = bytes(padded[idx * 4 : idx * 4 + 8])
        key[idx * 16 : idx * 16 + 16] = hashlib.md5(chunk).digest()
    return bytes(key)


def _on_video_decrypt_prefix(key: bytes, buf: bytes, offset: int) -> bytes:
    if not key:
        return bytes(buf)
    size = len(buf)
    out = bytearray(buf)
    max_i = min(0x80, max(0, size - max(0, offset)))
    for idx in range(max_i):
        out[offset + idx] ^= key[(key[idx] + size) % 0x80]
        out[offset + idx] ^= (size % 0xFD)
    return bytes(out)


def _xstream_head_size_for_type(frame_type: int, data: bytes) -> int:
    if frame_type in (0xEA, 0xEC, 0xED, 0xEE):
        return data[4] + 5
    if frame_type == 0xFC:
        return 8
    if frame_type in (0xF9, 0xFA, 0xFD):
        return 8
    return 0x10


def _xstream_payload_len_for_type(frame_type: int, data: bytes) -> int:
    if frame_type == 0xEA:
        return int.from_bytes(data[0x12:0x14], "little")
    if frame_type == 0xEC:
        return int.from_bytes(data[0x14:0x18], "little")
    if frame_type == 0xED:
        return int.from_bytes(data[0x0C:0x10], "little")
    if frame_type == 0xEE:
        return int.from_bytes(data[0x10:0x14], "little")
    if frame_type in (0xF9, 0xFA):
        return int.from_bytes(data[0x06:0x08], "little")
    if frame_type == 0xFC:
        return 8 + int.from_bytes(data[0x0C:0x10], "little")
    if frame_type == 0xFD:
        return data[4] | (data[5] << 8) | (data[6] << 16)
    return data[0x0C] | (data[0x0D] << 8) | (data[0x0E] << 16)


def _xstream_video_decrypt_offset(frame_type: int, data: bytes) -> int:
    # Mirrors CSTDStream::ParseHead + CStream::GetHeadSize for video subtype-0
    # frames. This decrypt offset is not the same as the transport framing head.
    if frame_type in (0xFC, 0xFE):
        return 0x10
    if frame_type in (0xEC, 0xEE):
        mode = (data[8] >> 2) & 0x0F
        return 0x14 if mode == 0 else 0x18
    return _xstream_head_size_for_type(frame_type, data)


def _parse_xstream_from_payloads(payloads: Iterable[bytes]) -> list[tuple[int, int, int, bytes]]:
    buffer = bytearray()
    frames: list[tuple[int, int, int, bytes]] = []
    for payload in payloads:
        if not payload:
            continue
        buffer.extend(payload)
        while True:
            if len(buffer) < 4:
                break
            if not (buffer[0] == 0 and buffer[1] == 0 and buffer[2] == 1):
                idx = buffer.find(b"\x00\x00\x01", 1)
                if idx < 0:
                    buffer.clear()
                    break
                del buffer[:idx]
                continue
            frame_type = buffer[3]
            if len(buffer) < 5:
                break
            head = _xstream_head_size_for_type(frame_type, buffer)
            if len(buffer) < head:
                break
            try:
                payload_len = _xstream_payload_len_for_type(frame_type, buffer)
            except Exception:
                del buffer[:3]
                continue
            total = head + payload_len
            if payload_len < 0 or total <= 0:
                del buffer[:3]
                continue
            if len(buffer) < total:
                break
            frame = bytes(buffer[:total])
            frames.append((frame_type, head, payload_len, frame))
            del buffer[:total]
    return frames


def _scan_annexb(payload: bytes) -> tuple[Counter[int], Counter[int]]:
    h264: Counter[int] = Counter()
    h265: Counter[int] = Counter()
    pos = 0
    while True:
        idx = payload.find(b"\x00\x00\x00\x01", pos)
        if idx < 0 or idx + 5 > len(payload):
            break
        nal = payload[idx + 4]
        h264[nal & 0x1F] += 1
        h265[(nal >> 1) & 0x3F] += 1
        pos = idx + 4
    return h264, h265


def _parse_inner_d0_payload(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 16:
        return None
    if not payload.startswith(b"\x00\x00\x00\x01\x02\x01\xd0"):
        return None
    opcode_be = int.from_bytes(payload[6:8], "big")
    opcode_le = int.from_bytes(payload[6:8], "little")
    tail = payload[7]
    seq_slot = ((tail - 3) // 2) if tail >= 3 and (tail - 3) % 2 == 0 else None
    return {
        "prefix_hex": payload[:7].hex(),
        "opcode_be": f"0x{opcode_be:04x}",
        "opcode_le": f"0x{opcode_le:04x}",
        "opcode_class": f"0x{payload[6]:02x}",
        "tail": tail,
        "seq_slot": seq_slot,
        "stamp_head_hex": payload[8:16].hex(),
        "body_head_hex": payload[16:48].hex(),
        "payload_len": len(payload),
    }


def _parse_hevc_annexb_unit(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 6 or not payload.startswith(b"\x00\x00\x00\x01"):
        return None
    nal_header = payload[4:6]
    nal_type = (nal_header[0] >> 1) & 0x3F
    layer_id = ((nal_header[0] & 0x01) << 5) | (nal_header[1] >> 3)
    temporal_id_plus1 = nal_header[1] & 0x07
    return {
        "nal_header_hex": nal_header.hex(),
        "h265_nal_type": nal_type,
        "h265_layer_id": layer_id,
        "h265_temporal_id_plus1": temporal_id_plus1,
        "body_head_hex": payload[6:38].hex(),
        "payload_len": len(payload),
    }


def _parse_fc_payload(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 8:
        return None
    meta_u32_le = int.from_bytes(payload[0:4], "little")
    blob_len_le = int.from_bytes(payload[4:8], "little")
    blob = payload[8:]
    hevc = _parse_hevc_annexb_unit(blob)
    return {
        "meta_u32_le": meta_u32_le,
        "meta_u32_hex": f"0x{meta_u32_le:08x}",
        "blob_len_le": blob_len_le,
        "actual_blob_len": len(blob),
        "blob_len_matches": blob_len_le == len(blob),
        "header_hex": payload[:8].hex(),
        "blob_head_hex": blob[:48].hex(),
        "blob_tail_hex": blob[-32:].hex() if blob else "",
        "blob_starts_annexb": blob.startswith(b"\x00\x00\x00\x01"),
        "blob_second_startcode_at": blob.find(b"\x00\x00\x00\x01", 4),
        "blob_h265_nal_type": hevc["h265_nal_type"] if hevc else None,
        "blob": blob,
    }


def _summarize_xstream_payload_sizes(
    xstream_frames: Iterable[tuple[int, int, int, bytes]],
    *,
    target_types: set[int],
) -> dict[str, dict[str, int]]:
    grouped: dict[str, Counter[int]] = {}
    for frame_type, _, payload_len, _ in xstream_frames:
        if frame_type not in target_types:
            continue
        key = f"0x{frame_type:02x}"
        grouped.setdefault(key, Counter())
        grouped[key][payload_len] += 1
    return {
        frame_type: {str(length): count for length, count in counter.most_common(12)}
        for frame_type, counter in grouped.items()
    }


def _summarize_fa_audio_candidate(
    xstream_frames: Iterable[tuple[int, int, int, bytes]],
) -> dict[str, Any] | None:
    payloads = [frame[head : head + payload_len] for frame_type, head, payload_len, frame in xstream_frames if frame_type == 0xFA]
    if not payloads:
        return None
    lengths = Counter(len(payload) for payload in payloads)
    merged = b"".join(payloads)
    byte_counts = Counter(merged)
    g711aish = [0x55, 0xD5, 0x54, 0x56, 0x57, 0xD4, 0xD6, 0xD7]
    g711aish_ratio = (sum(byte_counts[value] for value in g711aish) / len(merged)) if merged else 0.0
    likely_codec = ""
    if lengths == Counter({320: len(payloads)}) and g711aish_ratio > 0.50:
        likely_codec = "g711a_like"
    return {
        "frame_count": len(payloads),
        "payload_sizes": {str(length): count for length, count in lengths.most_common(8)},
        "byte_top": {f"0x{value:02x}": count for value, count in byte_counts.most_common(12)},
        "g711aish_ratio": round(g711aish_ratio, 4),
        "likely_codec": likely_codec,
    }


def _scan_avcc(payload: bytes, length_size: int = 4, max_scan: int = 32) -> tuple[Counter[int], Counter[int]]:
    if len(payload) < length_size + 1:
        return Counter(), Counter()
    pos = 0
    parsed = 0
    h264: Counter[int] = Counter()
    h265: Counter[int] = Counter()
    while pos + length_size <= len(payload) and parsed < max_scan:
        nal_len = int.from_bytes(payload[pos : pos + length_size], "big")
        pos += length_size
        if nal_len <= 0 or pos + nal_len > len(payload):
            break
        nal = payload[pos]
        h264[nal & 0x1F] += 1
        h265[(nal >> 1) & 0x3F] += 1
        pos += nal_len
        parsed += 1
    if parsed < 3:
        return Counter(), Counter()
    return h264, h265


def analyze_local_media_bootstrap_frames(
    frames: Iterable[TcpFrame],
    *,
    random_str: str = "",
    media_random_str: str = "",
    vekey1: str = "",
    controller_status: str = "",
) -> dict[str, Any]:
    frame_list = list(frames)

    def _frame_msg_type(item: Any) -> int:
        if isinstance(item, dict):
            return _intish(item.get("msg_type"), 0)
        return _intish(getattr(item, "msg_type", 0), 0)

    def _frame_msg_id(item: Any) -> int:
        if isinstance(item, dict):
            return _intish(item.get("msg_id"), 0)
        return _intish(getattr(item, "msg_id", 0), 0)

    def _frame_session_id(item: Any) -> int:
        if isinstance(item, dict):
            return _intish(item.get("session_id"), 0)
        return _intish(getattr(item, "session_id", 0), 0)

    def _frame_payload_len(item: Any) -> int:
        if isinstance(item, dict):
            payload_len = item.get("payload_len")
            if payload_len is not None:
                return _intish(payload_len, 0)
            payload = item.get("payload")
            if isinstance(payload, (bytes, bytearray)):
                return len(payload)
            return 0
        payload = getattr(item, "payload", b"")
        return len(payload) if isinstance(payload, (bytes, bytearray)) else 0

    def _frame_payload_bytes(item: Any) -> bytes:
        if isinstance(item, dict):
            payload = item.get("payload")
            if isinstance(payload, (bytes, bytearray)):
                return bytes(payload)
            payload_b64 = item.get("payload_b64")
            if isinstance(payload_b64, str) and payload_b64:
                try:
                    return base64.b64decode(payload_b64.encode("ascii"))
                except Exception:
                    return b""
            return b""
        payload = getattr(item, "payload", b"")
        return bytes(payload) if isinstance(payload, (bytes, bytearray)) else b""

    def _frame_payload_head_hex(item: Any) -> str:
        if isinstance(item, dict):
            return str(item.get("payload_head_hex") or "")
        payload = _frame_payload_bytes(item)
        return payload[:32].hex()

    data_frames = [item for item in frame_list if _frame_msg_type(item) == 1]
    normalized_media_random_str = _normalize_media_random_str(media_random_str)
    normalized_vekey1 = _normalize_media_random_str(vekey1)
    effective_decrypt_random_str = normalized_vekey1 or normalized_media_random_str or str(random_str or "")
    summary: dict[str, Any] = {
        "status": "unknown",
        "random_str_present": bool(random_str),
        "media_random_str_present": bool(normalized_media_random_str),
        "vekey1_present": bool(normalized_vekey1),
        "controller_status": controller_status,
        "data_frame_count": len(data_frames),
        "data_total_bytes": sum(_frame_payload_len(item) for item in data_frames),
    }
    if random_str:
        summary["random_str_len"] = len(random_str)
    if normalized_media_random_str:
        summary["media_random_str_len"] = len(normalized_media_random_str)
    if normalized_vekey1:
        summary["vekey1_len"] = len(normalized_vekey1)
        summary["decrypt_random_str_source"] = "vekey1"
    elif normalized_media_random_str:
        summary["decrypt_random_str_source"] = "media_random_str"
    elif random_str:
        summary["decrypt_random_str_source"] = "agent_random_str"

    if not data_frames:
        if controller_status in {"controller_readying", "controller_pending", "realplay_started"}:
            summary["status"] = "waiting_first_video_packet"
            summary["next_action"] = "capture_first_0x2afe"
        else:
            summary["status"] = "no_media_transport"
            summary["next_action"] = "continue_controller_sequence"
        return summary

    summary["first_data_frames"] = [
        {
            "msg_id": _frame_msg_id(item),
            "session_id": _frame_session_id(item),
            "payload_len": _frame_payload_len(item),
            "payload_head_hex": _frame_payload_head_hex(item),
        }
        for item in data_frames[:5]
    ]

    payloads = [payload for item in data_frames if (payload := _frame_payload_bytes(item))]
    if not payloads:
        summary["status"] = "transport_data_only"
        summary["next_action"] = "capture_more_msg_type1_frames"
        return summary
    xstream_frames = _parse_xstream_from_payloads(payloads)
    summary["xstream_frame_count"] = len(xstream_frames)
    if xstream_frames:
        summary["xstream_types"] = {
            f"0x{frame_type:02x}": count
            for frame_type, count in sorted(Counter(frame_type for frame_type, _, _, _ in xstream_frames).items())
        }
        payload_size_summary = _summarize_xstream_payload_sizes(
            xstream_frames,
            target_types={0xF9, 0xFA, 0xFC, 0xFD},
        )
        if payload_size_summary:
            summary["xstream_payload_sizes"] = payload_size_summary
        fa_audio = _summarize_fa_audio_candidate(xstream_frames)
        if fa_audio:
            summary["audio_candidate"] = fa_audio

    video_types = {0xEC, 0xED, 0xEE, 0xFD, 0xFC, 0xFE}
    decrypt_types = {0xFC, 0xFE, 0xEC, 0xEE}
    decrypt_key = _build_stream_decrypt_key(effective_decrypt_random_str)
    if decrypt_key:
        summary["decrypt_key_len"] = len(decrypt_key)
        summary["decrypt_key_strategy"] = "random_str_md5_blocks"

    merged = bytearray()
    annexb_h264: Counter[int] = Counter()
    annexb_h265: Counter[int] = Counter()
    avcc4_h264: Counter[int] = Counter()
    avcc4_h265: Counter[int] = Counter()
    avcc2_h264: Counter[int] = Counter()
    avcc2_h265: Counter[int] = Counter()
    decrypted_video_frames = 0
    fd_hevc_frames: list[dict[str, Any]] = []
    fc_entries: list[dict[str, Any]] = []

    for frame_type, head, payload_len, frame in xstream_frames:
        if frame_type not in video_types:
            continue
        if decrypt_key and frame_type in decrypt_types:
            frame = _on_video_decrypt_prefix(
                decrypt_key, frame, _xstream_video_decrypt_offset(frame_type, frame)
            )
            decrypted_video_frames += 1
        payload = frame[head : head + payload_len]
        if not payload:
            continue
        scan_payload = payload
        if frame_type == 0xFC and len(payload) >= 8:
            fc = _parse_fc_payload(payload)
            if fc:
                fc_entry = {k: v for k, v in fc.items() if k != "blob"}
                fc_entries.append(fc_entry)
                scan_payload = fc["blob"]
        hevc = _parse_hevc_annexb_unit(scan_payload)
        if hevc and frame_type == 0xFD:
            fd_hevc_frames.append(hevc)
        merged.extend(scan_payload)
        h264, h265 = _scan_annexb(scan_payload)
        annexb_h264.update(h264)
        annexb_h265.update(h265)
        a4_h264, a4_h265 = _scan_avcc(scan_payload, 4)
        avcc4_h264.update(a4_h264)
        avcc4_h265.update(a4_h265)
        a2_h264, a2_h265 = _scan_avcc(scan_payload, 2)
        avcc2_h264.update(a2_h264)
        avcc2_h265.update(a2_h265)

    summary["decrypted_video_frames"] = decrypted_video_frames
    summary["merged_video_bytes"] = len(merged)
    if merged:
        summary["merged_video_head_hex"] = bytes(merged[:64]).hex()
    if annexb_h264:
        summary["annexb_h264_nals"] = {str(key): value for key, value in annexb_h264.most_common(10)}
    if annexb_h265:
        summary["annexb_h265_nals"] = {str(key): value for key, value in annexb_h265.most_common(10)}
    if avcc4_h264:
        summary["avcc4_h264_nals"] = {str(key): value for key, value in avcc4_h264.most_common(10)}
    if avcc4_h265:
        summary["avcc4_h265_nals"] = {str(key): value for key, value in avcc4_h265.most_common(10)}
    if avcc2_h264:
        summary["avcc2_h264_nals"] = {str(key): value for key, value in avcc2_h264.most_common(10)}
    if avcc2_h265:
        summary["avcc2_h265_nals"] = {str(key): value for key, value in avcc2_h265.most_common(10)}
    if fd_hevc_frames:
        summary["fd_hevc_frame_count"] = len(fd_hevc_frames)
        summary["fd_hevc_nal_types"] = {
            str(key): value
            for key, value in Counter(item["h265_nal_type"] for item in fd_hevc_frames).most_common(10)
        }
        summary["fd_hevc_first_frames"] = fd_hevc_frames[:6]
    if fc_entries:
        summary["fc_frame_count"] = len(fc_entries)
        summary["fc_first_frames"] = fc_entries[:4]
    fa_320_frames = sum(1 for frame_type, _, payload_len, _ in xstream_frames if frame_type == 0xFA and payload_len == 320)
    if fa_320_frames:
        summary["audio_candidate_fixed_320_frames"] = fa_320_frames

    if merged and (annexb_h264 or annexb_h265 or avcc4_h264 or avcc4_h265 or avcc2_h264 or avcc2_h265):
        summary["status"] = "video_payload_detected_after_decrypt" if decrypted_video_frames else "video_payload_detected"
        summary["next_action"] = "implement_frame_demux"
    elif xstream_frames:
        summary["status"] = "xstream_detected"
        summary["next_action"] = "inspect_first_video_0x2afe"
    else:
        summary["status"] = "transport_data_only"
        summary["next_action"] = "capture_more_msg_type1_frames"
    return summary


def _ensure_local_bootstrap_summary(
    probe_result: dict[str, Any],
    *,
    controller_status: str = "",
    random_str: str = "",
    media_random_str: str = "",
    vekey1: str = "",
) -> dict[str, Any]:
    existing = probe_result.get("local_bootstrap_summary")
    if isinstance(existing, dict) and existing:
        summary = dict(existing)
        if controller_status:
            summary["controller_status"] = controller_status
        if random_str:
            summary["random_str_present"] = True
            summary.setdefault("random_str_len", len(random_str))
        normalized_media_random_str = _normalize_media_random_str(media_random_str)
        normalized_vekey1 = _normalize_media_random_str(vekey1)
        if normalized_media_random_str:
            summary["media_random_str_present"] = True
            summary.setdefault("media_random_str_len", len(normalized_media_random_str))
        if normalized_vekey1:
            summary["vekey1_present"] = True
            summary.setdefault("vekey1_len", len(normalized_vekey1))
            summary["decrypt_random_str_source"] = "vekey1"
        elif normalized_media_random_str:
            summary["decrypt_random_str_source"] = "media_random_str"
        return summary
    return analyze_local_media_bootstrap_frames(
        ((probe_result.get("frames") or {}).get("data_frames") or []),
        random_str=random_str,
        media_random_str=media_random_str,
        vekey1=vekey1,
        controller_status=controller_status,
    )


_SDK_INTERNAL_OPCODE_MAP: dict[int, str] = {
    0x2AF9: "Login",
    0x2AFC: "CmdMediaCtrl",
    0x2AFD: "DevPtl",
    0x2AFE: "SendNextData",
    0x2AFF: "MainLinkAbnormalDisconnect",
}


def _probe_control_frames(probe_result: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(probe_result, dict):
        return []
    rows = probe_result.get("rows")
    if isinstance(rows, list):
        flattened: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_frames = row.get("frames")
            if isinstance(row_frames, list):
                flattened.extend(item for item in row_frames if isinstance(item, dict))
        if flattened:
            return flattened
    frames = probe_result.get("frames")
    if not isinstance(frames, dict):
        return []
    control_frames = frames.get("control_frames")
    if not isinstance(control_frames, list):
        first_frames = frames.get("first_frames")
        if isinstance(first_frames, list):
            return [item for item in first_frames if isinstance(item, dict)]
        return []
    return [item for item in control_frames if isinstance(item, dict)]


def _probe_data_frames(probe_result: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(probe_result, dict):
        return []
    rows = probe_result.get("rows")
    if isinstance(rows, list):
        flattened: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_frames = row.get("data_frames")
            if isinstance(row_frames, list):
                flattened.extend(item for item in row_frames if isinstance(item, dict))
        if flattened:
            return flattened
    frames = probe_result.get("frames")
    if not isinstance(frames, dict):
        return []
    data_frames = frames.get("data_frames")
    if not isinstance(data_frames, list):
        return []
    return [item for item in data_frames if isinstance(item, dict)]


def _frame_json_payload(frame: dict[str, Any]) -> dict[str, Any]:
    for key in ("dataenc_decrypted_json", "aes_decrypted_json", "dataenc_json", "aes_json"):
        value = frame.get(key)
        if isinstance(value, dict):
            return value
    payload_text = frame.get("payload_text")
    if isinstance(payload_text, str) and payload_text.strip().startswith("{"):
        try:
            parsed = json.loads(payload_text.strip())
        except Exception:
            parsed = {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _controller_stage_name(cmd: int) -> str:
    return {
        0x0585: "claim_request",
        0x0586: "claim_response",
        0x03E8: "login_request",
        0x03E9: "login_response",
        0x0582: "media_control_request",
        0x0583: "media_control_response",
        0x061A: "post_login_request_061a",
        0x061B: "post_login_response_061b",
        0x0550: "post_login_request_0550",
        0x0551: "post_login_response_0551",
        0x03FC: "post_login_request_03fc",
        0x03FD: "post_login_response_03fd",
        0x064A: "post_login_request_064a",
        0x064B: "post_login_response_064b",
        0x064C: "post_login_request_064c",
        0x064D: "post_login_response_064d",
        0x0412: "post_login_request_0412",
        0x0413: "post_login_response_0413",
        0x05AD: "controller_error_response_05ad",
    }.get(int(cmd), f"cmd_0x{int(cmd):04x}")


def _intish(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            return int(text, 0)
        except Exception:
            return default
    return default


def _classify_media_control_ret(ret: int | None) -> str:
    if ret == 100:
        return "started"
    if ret == 101:
        return "controller_readying"
    if ret == 103:
        return "controller_pending"
    if ret == 117:
        return "controller_rejected"
    if ret is None:
        return "unknown"
    return f"ret_{ret}"


def analyze_live_controller_flow(probe_result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(probe_result, dict):
        probe_result = {}
    control_frames = _probe_control_frames(probe_result)
    local_bootstrap = probe_result.get("local_bootstrap_summary")
    claim_info = probe_result.get("claim") if isinstance(probe_result.get("claim"), dict) else {}
    summary: dict[str, Any] = {
        "internal_opcode_map": {f"0x{key:04x}": value for key, value in sorted(_SDK_INTERNAL_OPCODE_MAP.items())},
        "request_path": "OnUserMsg -> ToRealPlay -> Dev_SendMsg(..., 0x2afc, ...)",
        "stages": [],
        "status": "unknown",
        "signals": {},
    }
    if not control_frames:
        summary["status"] = "no_control_frames"
        return summary

    stages: list[dict[str, Any]] = []
    claim_ok = False
    login_ok = False
    media_control_ret: int | None = None
    media_control_state = "unknown"
    saw_data_delivery = False
    saw_controller_error = False
    session_id_after_login = ""
    ret_counts: Counter[int] = Counter()
    cmd_counts: Counter[str] = Counter()

    for frame in control_frames:
        cmd = _intish(frame.get("cmd"), 0)
        cmd_counts[f"0x{cmd:04x}"] += 1
        payload_json = _frame_json_payload(frame)
        ret_raw = payload_json.get("Ret")
        ret_value: int | None = None
        if isinstance(ret_raw, int):
            ret_value = ret_raw
        elif isinstance(ret_raw, str):
            try:
                ret_value = int(ret_raw, 0)
            except Exception:
                ret_value = None
        if ret_value is not None:
            ret_counts[ret_value] += 1

        stage = {
            "cmd": f"0x{cmd:04x}",
            "name": _controller_stage_name(cmd),
            "msg_id": _intish(frame.get("msg_id"), 0),
            "session_id": _intish(frame.get("session_id"), 0),
        }
        if ret_value is not None:
            stage["ret"] = ret_value

        if cmd == 0x0586:
            claim_ok = ret_value == 100
            if payload_json:
                stage["encrypt_algo"] = str(payload_json.get("EncryptAlgo") or "")
                stage["login_encryption_type"] = sorted(
                    key for key, value in (payload_json.get("LoginEncryptionType") or {}).items() if value
                )
                stage["data_encryption_type"] = sorted(
                    key for key, value in (payload_json.get("DataEncryptionType") or {}).items() if value
                )
        elif cmd == 0x03E9:
            login_ok = ret_value == 100
            if payload_json:
                session_id_after_login = str(payload_json.get("SessionID") or "")
                if session_id_after_login:
                    stage["runtime_session"] = session_id_after_login
                channel_num = payload_json.get("ChannelNum")
                if channel_num is not None:
                    stage["channel_num"] = channel_num
        elif cmd == 0x0583:
            media_control_ret = ret_value
            media_control_state = _classify_media_control_ret(ret_value)
            if payload_json:
                stage["name_field"] = str(payload_json.get("Name") or "")
        elif cmd in (0x061B, 0x0551, 0x03FD, 0x064B, 0x064D, 0x0413):
            saw_data_delivery = True
        elif cmd == 0x05AD:
            saw_controller_error = True

        stages.append(stage)

    if claim_ok and login_ok and media_control_state == "started":
        status = "realplay_started"
    elif claim_ok and login_ok and media_control_state in {"controller_readying", "controller_pending"}:
        status = media_control_state
    elif claim_ok and login_ok:
        status = "login_complete"
    elif claim_ok:
        status = "claim_complete"
    else:
        status = "controller_incomplete"

    if saw_controller_error and status == "realplay_started":
        status = "realplay_started_with_controller_errors"
    elif saw_controller_error and status not in {"realplay_started", "controller_readying"}:
        status = "controller_error"

    next_action = "inspect"
    recommended_profile = ""
    if not claim_ok:
        next_action = "complete_claim"
    elif claim_ok and not login_ok:
        next_action = "refresh_login_token_or_rebuild_0x03e8"
    elif login_ok and media_control_ret is None:
        next_action = "send_first_0x582"
        recommended_profile = "historical_order_built_queries_dynamic_second582"
    elif media_control_state == "controller_pending":
        next_action = "continue_post_login_sequence"
        recommended_profile = "historical_order_built_queries_dynamic_second582"
    elif media_control_state == "controller_readying":
        next_action = "continue_post_login_sequence"
        recommended_profile = "historical_order_built_queries_dynamic_second582"
    elif saw_controller_error:
        next_action = "inspect_0x05ad_or_main_link_abnormal"
    elif status.startswith("realplay_started"):
        next_action = "collect_media_frames"

    local_status = ""
    if isinstance(local_bootstrap, dict):
        local_status = str(local_bootstrap.get("status") or "")
        if local_status == "waiting_first_video_packet" and status in {"controller_readying", "controller_pending", "realplay_started"}:
            next_action = "capture_first_0x2afe"
        elif local_status in {"xstream_detected", "transport_data_only"}:
            next_action = "inspect_first_video_0x2afe"
        elif local_status == "video_payload_detected_after_decrypt":
            next_action = "implement_frame_demux"

    summary["stages"] = stages
    summary["status"] = status
    summary["signals"] = {
        "claim_ok": claim_ok,
        "login_ok": login_ok,
        "media_control_ret": media_control_ret,
        "media_control_state": media_control_state,
        "session_id_after_login": session_id_after_login,
        "saw_send_next_data_family": saw_data_delivery,
        "saw_main_link_abnormal_path": saw_controller_error,
        "cmd_counts": dict(sorted(cmd_counts.items())),
        "ret_counts": {str(key): value for key, value in sorted(ret_counts.items())},
        "second_success_replay_state": str(claim_info.get("second_success_replay_state") or ""),
    }
    if local_status:
        summary["signals"]["local_bootstrap_status"] = local_status
    if session_id_after_login:
        summary["session_id_after_login"] = session_id_after_login
        summary["runtime_session"] = session_id_after_login
    summary["next_action"] = next_action
    if recommended_profile:
        summary["recommended_profile"] = recommended_profile
    return summary


def build_plain_opmonitor_claim_payload(
    *,
    session_int: int,
    channel: int,
    stream_type: str,
    trans_mode: str,
    combine_mode: str,
    session_hex_width: int = 10,
) -> bytes:
    session_hex = _format_session_hex(session_int, width=session_hex_width)
    payload_obj = {
        "Name": "OPMonitor",
        "OPMonitor": {
            "Action": "Claim",
            "Action1": "Start",
            "Parameter": {
                "Channel": int(channel),
                # The device protocol expects the historical misspelling.
                "CombinMode": combine_mode,
                "StreamType": stream_type,
                "TransMode": trans_mode,
            },
        },
        "SessionID": session_hex,
    }
    return json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\x00"


def _cmd_from_big_endian_code(code: int) -> int:
    packed = struct.pack(">I", int(code) & 0xFFFFFFFF)
    return struct.unpack("<H", packed[2:4])[0]


def build_plain_claim_replay_followups(
    *,
    session_int: int,
    channel: int,
    stream_type: str,
    trans_mode: str,
    combine_mode: str,
    msg_id: int,
    code: int,
    code_endian: str = "be",
    session_hex_width: int = 10,
    replay_count: int = 1,
    first_delay: float = 0.35,
    delay_step: float = 0.45,
    msg_id_step: int = 1,
) -> list[dict[str, Any]]:
    payload = build_plain_opmonitor_claim_payload(
        session_int=session_int,
        channel=channel,
        stream_type=stream_type,
        trans_mode=trans_mode,
        combine_mode=combine_mode,
        session_hex_width=session_hex_width,
    )
    frames: list[dict[str, Any]] = []
    safe_count = max(0, int(replay_count))
    base_msg_id = int(msg_id)
    for replay_index in range(safe_count):
        frames.append(
            {
                "msg_type": 0,
                "session_id": int(session_int),
                "msg_id": base_msg_id + int(msg_id_step) * (replay_index + 1),
                "code": int(code),
                "cmd": _cmd_from_big_endian_code(int(code)),
                "code_endian": str(code_endian or "be"),
                "payload_bytes": payload,
                "delay_before": max(0.0, float(first_delay) + float(delay_step) * replay_index),
                "send_phase": "plain_claim_replay",
                "controller_profile": "shared_link_replay_window",
            }
        )
    return frames


def _stream_name_to_gwm_stream_id(stream_type: str) -> int:
    text = str(stream_type or "").strip().lower()
    if text in {"main", "mainstream"}:
        return 0
    if text in {"extra1", "extra", "sub", "substream"}:
        return 1
    if text in {"extra2", "sub2"}:
        return 2
    return 1


def _build_gwm_mid(channel: int, stream_id: int) -> str:
    return str(int(stream_id) + int(channel) * 2)


def _gwm_md5_hex(text: str) -> str:
    return hashlib.md5(str(text or "").encode("utf-8", errors="ignore")).hexdigest()


def build_gwm_start_video_http_payload(
    *,
    serial_number: str,
    authcode: str,
    channel: int,
    stream_id: int,
    token_username: str = "",
    username: str = "",
    password: str = "",
    uuid_text: str = "",
    app_key: str = "",
    vendor_name: str = "",
    include_channel_stream: bool = False,
    include_context: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "sn": str(serial_number or ""),
        "mid": _build_gwm_mid(channel, stream_id),
        "msg": "start_video_req",
        "auth": str(authcode or ""),
    }
    token_username = str(token_username or "").strip()
    if token_username:
        payload["t"] = token_username
    else:
        payload["u"] = str(username or "")
        payload["p"] = str(password or "")
    if include_channel_stream:
        payload["channel"] = int(channel)
        payload["stream"] = int(stream_id)
    if include_context:
        if str(uuid_text or "").strip():
            payload["uuid"] = str(uuid_text or "").strip()
        if str(app_key or "").strip():
            payload["appkey"] = str(app_key or "").strip()
        if str(vendor_name or "").strip():
            payload["vendorname"] = str(vendor_name or "").strip()
    return payload


def _build_http_root_url(*, host: str, port: int, prefer_https: bool = True) -> str:
    safe_host = str(host or "").strip()
    safe_port = int(port or 0)
    if not safe_host or safe_port < 1:
        return ""
    scheme = "https" if prefer_https or safe_port == 443 else "http"
    return f"{scheme}://{safe_host}:{safe_port}/"


def _extract_host_port_from_url(url: str, default_port: int = 0) -> tuple[str, int]:
    text = str(url or "").strip()
    if not text:
        return "", int(default_port or 0)
    if "://" in text:
        parsed = urllib.parse.urlparse(text)
        return str(parsed.hostname or "").strip(), int(parsed.port or default_port or 0)
    host_part, sep, port_part = text.rpartition(":")
    if sep and host_part and port_part.isdigit():
        return host_part.strip(), int(port_part)
    return text, int(default_port or 0)


def _recv_until_suffix(
    sock: socket.socket,
    *,
    suffix: bytes,
    timeout: float,
    max_bytes: int = 8192,
) -> tuple[bytes, str]:
    deadline = time.time() + max(0.1, float(timeout))
    buffer = bytearray()
    while time.time() < deadline:
        sock.settimeout(max(0.1, min(1.0, deadline - time.time())))
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            continue
        if not chunk:
            break
        buffer.extend(chunk)
        if suffix and suffix in buffer:
            return bytes(buffer), ""
        if len(buffer) >= max_bytes:
            return bytes(buffer), "buffer_limit"
    return bytes(buffer), "timeout"


def run_idr_status_probe(
    *,
    serial_number: str,
    authcode: str,
    manufacturer_candidates: Iterable[str] | None = None,
    timeout: int = 10,
    user_agent: str = DEFAULT_STATUS_UA,
    ssl_verify: bool = False,
    content_types: Iterable[str] | None = None,
    base_urls: Iterable[str] | None = None,
) -> dict[str, Any]:
    bases = _dedupe(
        [
            *(list(base_urls or [])),
            *DEFAULT_IDR_STATUS_BASES,
        ]
    )
    manufacturer_values = _dedupe(
        [
            "",
            *(list(manufacturer_candidates or [])),
            "XM",
        ]
    )
    types = _dedupe([*(list(content_types or [])), "text/html", "application/json"])
    attempts: list[dict[str, Any]] = []
    selected: dict[str, Any] = {}
    selected_entry: dict[str, Any] = {}
    for base in bases:
        is_https = str(base or "").lower().startswith("https://")
        for manufacturer in manufacturer_values:
            for content_type in types:
                res = status_protocol_query(
                    serial_number=serial_number,
                    authcode=authcode,
                    base=base,
                    timeout=timeout,
                    ssl_verify=ssl_verify if is_https else False,
                    user_agent=user_agent,
                    content_type=content_type,
                    manufacturer=manufacturer,
                )
                parsed = parse_status_protocol_response(res.json_data)
                alarm = parse_alarm_center_response(res.json_data)
                body = parsed.get("body") if isinstance(parsed.get("body"), list) else []
                entry = normalize_idr_status_entry(body[0] if body and isinstance(body[0], dict) else {})
                attempt = {
                    "ok": res.ok,
                    "status": res.status,
                    "url": res.url,
                    "manufacturer": manufacturer,
                    "content_type": content_type,
                    "parsed": parsed,
                    "alarm_center": alarm,
                    "response_head": (res.text or "")[:600],
                    "error": res.error,
                }
                attempts.append(attempt)
                if entry and (
                    str(entry.get("ServerIP") or "").strip()
                    or str(entry.get("Status") or "").strip()
                    or entry.get("DevStatus") is not None
                    or entry.get("WakeUpEnable") is not None
                    or entry.get("DevHostStatus") is not None
                ):
                    selected = attempt
                    selected_entry = dict(entry)
                    break
            if selected:
                break
        if selected:
            break
    result = {
        "status": "error",
        "selected": selected,
        "entry": selected_entry,
        "attempts": attempts,
    }
    if selected_entry:
        result["status"] = "ok"
    elif attempts:
        result["status"] = "partial"
    return result


def build_wakeup_request_payload(
    *,
    serial_number: str,
    authcode: str,
    msg_type: str = "MSG_CLIENT_WAKEUP_REQ",
    cseq: str = "",
    ext_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "SerialNumber": str(serial_number or "").strip(),
        "MsgType": str(msg_type or "MSG_CLIENT_WAKEUP_REQ").strip(),
        "AuthCode": str(authcode or "").strip(),
        "CSeq": str(cseq or int(time.time() * 1000)),
    }
    if isinstance(ext_info, dict) and ext_info:
        payload["ExtInfo"] = ext_info
    return payload


def build_wakeup_request_text(
    *,
    serial_number: str,
    authcode: str,
    msg_type: str = "MSG_CLIENT_WAKEUP_REQ",
    cseq: str = "",
    ext_info: dict[str, Any] | None = None,
) -> str:
    payload = build_wakeup_request_payload(
        serial_number=serial_number,
        authcode=authcode,
        msg_type=msg_type,
        cseq=cseq,
        ext_info=ext_info,
    )
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + WAKEUP_SUFFIX.decode("ascii")


def run_wakeup_probe(
    *,
    serial_number: str,
    authcode: str,
    host: str = "",
    port: int = 0,
    msg_type: str = "MSG_CLIENT_WAKEUP_REQ",
    cseq: str = "",
    timeout: float = 10.0,
    ext_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target_host = str(host or "").strip()
    target_port = int(port or 0)
    result: dict[str, Any] = {
        "status": "error",
        "target_host": target_host or DEFAULT_WAKEUP_HOST,
        "target_port": target_port or DEFAULT_WAKEUP_PORT,
        "request": {},
        "response": {},
    }
    if not target_host or target_port < 1:
        result["status"] = "needs_idr_server"
        result["error"] = "missing_type8_server_ip_port"
        return result
    request_payload = build_wakeup_request_payload(
        serial_number=serial_number,
        authcode=authcode,
        msg_type=msg_type,
        cseq=cseq,
        ext_info=ext_info,
    )
    request_text = json.dumps(request_payload, ensure_ascii=False, separators=(",", ":")) + WAKEUP_SUFFIX.decode("ascii")
    result["request"] = {
        "payload": request_payload,
        "text": request_text,
        "text_len": len(request_text),
    }
    sock = _create_tcp_connection((result["target_host"], int(result["target_port"])), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(request_text.encode("utf-8"))
        raw, recv_error = _recv_until_suffix(sock, suffix=WAKEUP_SUFFIX, timeout=timeout, max_bytes=8192)
    finally:
        sock.close()
    raw_text = raw.decode("utf-8", errors="replace")
    trimmed_text = raw_text[:-4] if raw_text.endswith("XXEE") else raw_text
    parsed_json: Any = None
    if trimmed_text.strip():
        try:
            parsed_json = json.loads(trimmed_text.strip())
        except Exception:
            parsed_json = _decode_embedded_json_text(trimmed_text)
    ret_num = _intish((parsed_json or {}).get("RetNum") if isinstance(parsed_json, dict) else None, -999999)
    server_ip = str((parsed_json or {}).get("ServerIP") if isinstance(parsed_json, dict) else "" or "").strip()
    server_port = _intish((parsed_json or {}).get("ServerPort") if isinstance(parsed_json, dict) else None, 0)
    device_port = _intish((parsed_json or {}).get("DevicePort") if isinstance(parsed_json, dict) else None, 0)
    device_type = str((parsed_json or {}).get("DeviceType") if isinstance(parsed_json, dict) else "" or "").strip()
    result["response"] = {
        "recv_error": recv_error,
        "raw_len": len(raw),
        "raw_head_hex": raw[:128].hex(),
        "text": trimmed_text,
        "json": parsed_json,
        "ret_num": ret_num,
        "server_ip": server_ip,
        "server_port": server_port,
        "device_port": device_port,
        "device_type": device_type,
    }
    if server_ip and server_port > 0 and ret_num >= 0:
        result["status"] = "ok"
    elif parsed_json is not None or trimmed_text.strip():
        result["status"] = "partial"
    return result


def run_wakeup_cycle_probe(
    *,
    serial_number: str,
    authcode: str,
    idr_probe: dict[str, Any] | None = None,
    manufacturer_candidates: Iterable[str] | None = None,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_STATUS_UA,
    ssl_verify: bool = False,
    content_types: Iterable[str] | None = None,
    wakeup_host: str = "",
    wakeup_port: int = 0,
    msg_type: str = "MSG_CLIENT_WAKEUP_REQ",
    ext_info_variants: Iterable[dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    resolved_idr_probe = idr_probe if isinstance(idr_probe, dict) and idr_probe else run_idr_status_probe(
        serial_number=serial_number,
        authcode=authcode,
        manufacturer_candidates=manufacturer_candidates,
        timeout=max(3, int(timeout)),
        user_agent=user_agent,
        ssl_verify=ssl_verify,
        content_types=content_types,
    )
    entry = (resolved_idr_probe.get("entry") or {}) if isinstance(resolved_idr_probe, dict) else {}
    target_host = str(wakeup_host or entry.get("ServerIP") or "").strip()
    target_port = int(_intish(wakeup_port or entry.get("ServerPort"), 0))
    variants = list(ext_info_variants or [None, {"Cmd": "1"}])
    attempts: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "status": "error",
        "idr_status_probe": resolved_idr_probe,
        "target_host": target_host,
        "target_port": target_port,
        "attempts": attempts,
        "selected": {},
    }
    if not target_host or target_port < 1:
        result["status"] = "needs_idr_server"
        result["error"] = "idr_status_missing_server_ip_port"
        return result
    for ext_info in variants:
        attempt = run_wakeup_probe(
            serial_number=serial_number,
            authcode=authcode,
            host=target_host,
            port=target_port,
            msg_type=msg_type,
            timeout=timeout,
            ext_info=ext_info,
        )
        attempt["ext_info"] = dict(ext_info or {})
        attempts.append(attempt)
        response = (attempt.get("response") or {}) if isinstance(attempt, dict) else {}
        if str(response.get("server_ip") or "").strip() and _intish(response.get("server_port"), 0) > 0:
            result["status"] = "ok"
            result["selected"] = attempt
            return result
        if str(attempt.get("status") or "") in {"partial", "ok"} and not result.get("selected"):
            result["selected"] = attempt
    if attempts:
        statuses = {str(a.get("status") or "") for a in attempts if isinstance(a, dict)}
        if "partial" in statuses:
            result["status"] = "partial"
        elif "needs_idr_server" in statuses:
            result["status"] = "needs_idr_server"
        else:
            result["status"] = "error"
    return result


def build_gwm_start_video_socket_payload(
    *,
    serial_number: str,
    token_username: str,
    channel: int,
    stream_id: int,
    uuid_text: str,
    app_key: str,
    vendor_name: str,
    port_type: int = 6,
    extra_flag: int = 0,
) -> bytes:
    payload_obj = {
        "channel": str(int(channel)),
        "stream": str(int(stream_id)),
        "token": str(token_username or ""),
        "xtoken": _gwm_md5_hex(token_username),
        "uuid": str(uuid_text or ""),
        "appkey": str(app_key or ""),
        "vendorname": str(vendor_name or ""),
        "sn": str(serial_number or ""),
        "msg": "start_video_req",
    }
    payload_text = json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\x00"
    frame = bytearray(12 + len(payload_text))
    frame[0] = 0x46
    frame[1] = 0x01
    frame[2] = int(extra_flag) & 0xFF
    frame[3] = int(channel) & 0xFF
    struct.pack_into("<H", frame, 4, int(port_type) & 0xFFFF)
    struct.pack_into("<H", frame, 6, 0x0001)
    struct.pack_into("<H", frame, 8, 0)
    struct.pack_into("<H", frame, 10, len(payload_text) & 0xFFFF)
    frame[12:] = payload_text
    return bytes(frame)


def _extract_gwm_connect_host(raw: Any) -> tuple[str, int, dict[str, Any]]:
    meta: dict[str, Any] = {}
    candidate = ""
    default_port = 0x1E6C
    if isinstance(raw, dict):
        code = raw.get("code")
        if code is not None:
            meta["code"] = code
        for key in ("cryptor", "xtoken", "token"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                meta[key] = value.strip()
        for key in ("data", "url", "host", "ip", "addr", "address", "server"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                candidate = value.strip()
                break
            if isinstance(value, dict):
                for nested_key in ("url", "host", "ip", "addr", "address", "server"):
                    nested = value.get(nested_key)
                    if isinstance(nested, str) and nested.strip():
                        candidate = nested.strip()
                        break
                if candidate:
                    break
                nested_port = value.get("port")
                if isinstance(nested_port, (int, str)) and str(nested_port).strip():
                    try:
                        default_port = int(str(nested_port).strip(), 0)
                    except Exception:
                        pass
        if not candidate:
            for value in raw.values():
                if isinstance(value, str) and value.strip():
                    text = value.strip()
                    if "." in text or ":" in text or text.startswith("http"):
                        candidate = text
                        break
    elif isinstance(raw, str):
        candidate = raw.strip()
    if not candidate:
        return "", default_port, meta
    if "://" in candidate:
        parsed = urllib.parse.urlparse(candidate)
        host = str(parsed.hostname or "").strip()
        port = int(parsed.port or default_port)
        meta["source"] = candidate
        return host, port, meta
    if ":" in candidate:
        host_part, _, port_part = candidate.rpartition(":")
        if host_part and port_part.isdigit():
            meta["source"] = candidate
            return host_part.strip(), int(port_part), meta
    meta["source"] = candidate
    return candidate.strip(), default_port, meta


def _decode_embedded_json_text(raw_text: str) -> Any:
    text = str(raw_text or "").strip()
    if not text:
        return None
    candidates = [text]
    if "%" in text:
        decoded = urllib.parse.unquote(text)
        if decoded and decoded not in candidates:
            candidates.append(decoded)
    for candidate in candidates:
        trimmed = candidate.strip()
        if not trimmed.startswith("{"):
            continue
        try:
            return json.loads(trimmed)
        except Exception:
            continue
    return None


def _parse_gwm_frames(buffer: bytes) -> tuple[list[dict[str, Any]], bytes]:
    rows: list[dict[str, Any]] = []
    data = bytearray(buffer)
    while True:
        if len(data) < 12:
            break
        if data[0] != 0x46:
            idx = data.find(b"F", 1)
            if idx < 0:
                data.clear()
                break
            del data[:idx]
            continue
        payload_len = int.from_bytes(data[10:12], "little")
        total = 12 + payload_len
        if payload_len < 0 or len(data) < total:
            break
        payload = bytes(data[12:total])
        msg_id = int.from_bytes(data[6:8], "little")
        row: dict[str, Any] = {
            "version": data[1],
            "extra_flag": data[2],
            "channel": data[3],
            "service_type": int.from_bytes(data[4:6], "little"),
            "msg_id": msg_id,
            "payload_len": payload_len,
            "payload_head_hex": payload[:32].hex(),
        }
        if msg_id == 2:
            row["opcode"] = "0x7536"
        elif msg_id == 3:
            row["opcode"] = "0x7539"
        else:
            row["opcode"] = f"0x{msg_id:04x}"
        trimmed = payload.rstrip(b"\x00\r\n ")
        if trimmed.startswith(b"{"):
            try:
                text = trimmed.decode("utf-8")
                row["payload_text"] = text
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    row["payload_json"] = parsed
            except Exception:
                pass
        rows.append(row)
        del data[:total]
    return rows, bytes(data)


def run_gwm_live_probe(
    *,
    ams_url: str = "",
    server_host: str = "",
    server_port: int = 0,
    serial_number: str,
    authcode: str,
    channel: int,
    stream_type: str,
    token_username: str,
    username: str = "",
    password: str = "",
    uuid_text: str = "xmeye",
    app_key: str = "",
    vendor_name: str = "",
    timeout: float = 10.0,
    capture_seconds: float = 8.0,
    max_frames: int = 200,
    user_agent: str = DEFAULT_STATUS_UA,
    ssl_verify: bool = False,
) -> dict[str, Any]:
    stream_id = _stream_name_to_gwm_stream_id(stream_type)
    result: dict[str, Any] = {
        "status": "error",
        "http": {"attempts": []},
        "talker": {},
        "frames": {},
    }
    target_candidates: list[dict[str, Any]] = []
    safe_ams_url = str(ams_url or "").strip()
    safe_server_host = str(server_host or "").strip()
    safe_server_port = int(server_port or 0)
    if safe_ams_url:
        target_candidates.append(
            {
                "url": safe_ams_url,
                "source": "ams_url",
            }
        )
    if safe_server_host and safe_server_port > 0:
        target_candidates.append(
            {
                "url": _build_http_root_url(host=safe_server_host, port=safe_server_port, prefer_https=True),
                "source": "status_type7",
            }
        )
    deduped_target_candidates: list[dict[str, Any]] = []
    seen_target_keys: set[str] = set()
    for item in target_candidates:
        key = f"{item.get('source', '')}|{item.get('url', '')}"
        if key in seen_target_keys:
            continue
        seen_target_keys.add(key)
        deduped_target_candidates.append(item)
    target_candidates = deduped_target_candidates
    if not target_candidates:
        result["error"] = "gwm_target_missing"
        return result

    http_payload_candidates: list[dict[str, Any]] = []
    safe_token_username = str(token_username or "").strip()
    safe_username = str(username or "").strip()
    safe_password = str(password or "")
    payload_variants = [
        ("base", False, False),
        ("with_channel_stream", True, False),
        ("with_context", False, True),
        ("with_channel_stream_and_context", True, True),
    ]
    if safe_token_username:
        for variant_name, include_channel_stream, include_context in payload_variants:
            http_payload_candidates.append(
                {
                    "auth_mode": "token",
                    "variant": variant_name,
                    "payload": build_gwm_start_video_http_payload(
                        serial_number=serial_number,
                        authcode=authcode,
                        channel=channel,
                        stream_id=stream_id,
                        token_username=safe_token_username,
                        uuid_text=uuid_text,
                        app_key=app_key,
                        vendor_name=vendor_name,
                        include_channel_stream=include_channel_stream,
                        include_context=include_context,
                    ),
                }
            )
    if safe_username or safe_password:
        for variant_name, include_channel_stream, include_context in payload_variants:
            http_payload_candidates.append(
                {
                    "auth_mode": "userpass",
                    "variant": variant_name,
                    "payload": build_gwm_start_video_http_payload(
                        serial_number=serial_number,
                        authcode=authcode,
                        channel=channel,
                        stream_id=stream_id,
                        username=safe_username,
                        password=safe_password,
                        uuid_text=uuid_text,
                        app_key=app_key,
                        vendor_name=vendor_name,
                        include_channel_stream=include_channel_stream,
                        include_context=include_context,
                    ),
                }
            )
    if not http_payload_candidates:
        http_payload_candidates.append(
            {
                "auth_mode": "empty",
                "payload": build_gwm_start_video_http_payload(
                    serial_number=serial_number,
                    authcode=authcode,
                    channel=channel,
                    stream_id=stream_id,
                ),
            }
        )

    attempts: list[dict[str, Any]] = []
    best_http: HttpResult | None = None
    best_json: Any = None
    best_text = ""
    selected_attempt: dict[str, Any] = {}
    for target in target_candidates:
        target_url = str(target.get("url") or "").strip()
        if not target_url:
            continue
        for payload_entry in http_payload_candidates:
            auth_mode = str(payload_entry.get("auth_mode") or "").strip() or "unknown"
            variant_name = str(payload_entry.get("variant") or "").strip() or "base"
            http_payload = dict(payload_entry.get("payload") or {})
            http_result = http_json(
                url=target_url,
                method="POST",
                payload=http_payload,
                headers={
                    "Accept": "*/*",
                    "User-Agent": user_agent,
                    "Content-Type": "application/json",
                },
                timeout=max(3, int(timeout)),
                ssl_verify=ssl_verify,
            )
            parsed_json = http_result.json_data
            if parsed_json is None:
                parsed_json = _decode_embedded_json_text(http_result.text)
            parsed_text = (http_result.text or "").strip()
            host, port, meta = _extract_gwm_connect_host(parsed_json if parsed_json is not None else parsed_text)
            attempt = {
                "ok": http_result.ok,
                "status": http_result.status,
                "url": http_result.url,
                "target_source": str(target.get("source") or ""),
                "auth_mode": auth_mode,
                "variant": variant_name,
                "payload": http_payload,
                "response_head": parsed_text[:400],
                "response_json": parsed_json if isinstance(parsed_json, dict) else parsed_text[:800],
                "connect_host": host,
                "connect_port": port,
                "connect_meta": meta,
                "error": http_result.error,
            }
            attempts.append(attempt)
            if host:
                best_http = http_result
                best_json = parsed_json
                best_text = parsed_text
                selected_attempt = attempt
                break
        if best_http is not None:
            break
    result["http"] = {
        "target_candidates": target_candidates,
        "server_host": safe_server_host,
        "server_port": safe_server_port,
        "attempts": attempts,
        "selected_attempt": selected_attempt,
        "selected_response_head": best_text[:400],
    }
    host, port, connect_meta = _extract_gwm_connect_host(best_json if best_json is not None else best_text)
    if not host:
        result["error"] = "gwm_http_no_connect_host"
        result["status"] = "partial" if attempts else "error"
        return result

    sock = _create_tcp_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        req = build_gwm_start_video_socket_payload(
            serial_number=serial_number,
            token_username=token_username,
            channel=channel,
            stream_id=stream_id,
            uuid_text=uuid_text,
            app_key=app_key,
            vendor_name=vendor_name,
        )
        sock.sendall(req)
        received = bytearray()
        parsed_frames: list[dict[str, Any]] = []
        buffer = b""
        end_time = time.time() + max(0.5, float(capture_seconds))
        while time.time() < end_time and len(parsed_frames) < max_frames:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                continue
            if not chunk:
                break
            received.extend(chunk)
            buffer += chunk
            rows, buffer = _parse_gwm_frames(buffer)
            if rows:
                parsed_frames.extend(rows)
        control_rows = [item for item in parsed_frames if item.get("msg_id") == 2]
        data_rows = [item for item in parsed_frames if item.get("msg_id") == 3]
        cryptor = ""
        success_code = False
        for row in control_rows:
            payload_json = row.get("payload_json")
            if isinstance(payload_json, dict):
                code_value = _intish(payload_json.get("code"), -999999)
                if code_value in (0, 200):
                    success_code = True
                cryptor = str(payload_json.get("cryptor") or cryptor or "")
        result["talker"] = {
            "connect_host": host,
            "connect_port": port,
            "connect_meta": connect_meta,
            "request_payload_len": len(req),
            "request_payload_head_hex": req[:48].hex(),
            "cryptor": cryptor or None,
        }
        result["frames"] = {
            "total": len(parsed_frames),
            "control": len(control_rows),
            "data": len(data_rows),
            "control_frames": control_rows[:20],
            "data_frames": data_rows[:MEDIA_FRAME_SUMMARY_LIMIT],
            "raw_total_bytes": len(received),
            "raw_head_hex": bytes(received[:128]).hex(),
        }
        if data_rows:
            result["status"] = "ok"
        elif success_code or control_rows:
            result["status"] = "partial"
        else:
            result["status"] = "error"
        return result
    finally:
        sock.close()


class AgentTcpLiveProbe:
    def __init__(self, suffix: bytes = TCP_HANDSHAKE_SUFFIX) -> None:
        self.suffix = suffix

    def build_handshake(self, authcode: str, client_token: str, serial: str, session: str) -> bytes:
        raw = f"{authcode}:{client_token}:{serial}:{session}".encode("utf-8") + self.suffix
        return base64.b64encode(raw)

    def parse_handshake_response(self, decoded: bytes) -> dict[str, Any]:
        if decoded.endswith(self.suffix):
            decoded = decoded[: -len(self.suffix)]
        text = decoded.decode("utf-8", errors="replace")
        try:
            json_data = json.loads(text)
        except Exception:
            json_data = None
        return {
            "text": text,
            "json": json_data,
        }

def run_probe(
        self,
        *,
        host: str,
        port: int,
        authcode: str,
        client_token: str,
        serial: str,
        session: str,
        session_int: int,
        channel: int,
        stream_type: str,
        trans_mode: str,
        combine_mode: str,
        msg_id: int,
        code: int,
        code_endian: str,
        timeout: float,
        capture_seconds: float,
        max_frames: int,
        media_random_str: str = "",
        session_hex_width: int = 10,
        followup_frames: list[dict[str, Any]] | None = None,
        followup_delay: float = 0.0,
        initial_payload_text: str = "",
        initial_code: int | None = None,
        login_followup_builder: dict[str, Any] | None = None,
        skip_handshake: bool = False,
        ready_event: threading.Event | None = None,
        ready_timeout: float = 0.0,
        send_followups_on_silence: bool = False,
        response_trigger_followups: list[dict[str, Any]] | None = None,
        on_data_frame_payload: Callable[[bytes, str], None] | None = None,
        stop_event: threading.Event | None = None,
        extend_on_activity: bool = False,
        keepalive_replay_start_delay: float = 0.0,
        keepalive_replay_interval: float = 0.0,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "error",
            "agent_host": host,
            "agent_port": port,
            "handshake": {},
            "opmonitor": {},
            "frames": {},
        }
        sock = _create_tcp_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        try:
            if ready_event is not None:
                waited = max(0.0, float(ready_timeout))
                ready_ok = ready_event.wait(waited)
                result["bind_wait"] = {
                    "requested": True,
                    "timeout": waited,
                    "ready": bool(ready_ok),
                }
            leftover = b""
            sent_followups: list[dict[str, Any]] = []
            followup_send_error: dict[str, Any] | None = None
            response_triggered = False
            if skip_handshake:
                result["handshake"] = {
                    "ok": True,
                    "skipped": True,
                    "mode": "local_bind_proxy",
                }
            else:
                handshake_b64 = self.build_handshake(authcode, client_token, serial, session)
                handshake_text = f"{authcode}:{client_token}:{serial}:{session}"
                sent_info = {
                    "sent_b64": handshake_b64.decode("ascii", errors="ignore"),
                    "sent_text": handshake_text,
                    "sent_wire_text": _format_handshake_wire_text(handshake_text, self.suffix),
                    "sent_suffix_hex": self.suffix.hex(),
                }
                result["handshake"].update(sent_info)
                sock.sendall(handshake_b64)
                b64_resp, leftover, err = _recv_base64_message(sock, timeout=timeout, suffix=self.suffix)
                if not b64_resp:
                    result["handshake"] = {
                        **sent_info,
                        "ok": False,
                        "error": err or "no_response",
                    }
                    return result
                decoded, dec_err = _decode_base64_with_suffix(b64_resp, self.suffix)
                if decoded is None:
                    result["handshake"] = {
                        **sent_info,
                        "ok": False,
                        "error": dec_err or "decode_failed",
                    }
                    return result
                parsed = self.parse_handshake_response(decoded)
                result["handshake"] = {
                    **sent_info,
                    "ok": True,
                    "b64_len": len(b64_resp),
                    "decoded_len": len(decoded),
                    "parsed": parsed,
                    **_summarize_handshake_reply(b64_resp, parsed),
                }

            def _send_followup_dict(followup: dict[str, Any]) -> bool:
                nonlocal followup_send_error
                payload_bytes = bytes(followup.get("payload_bytes") or b"")
                followup_frame = _build_tcp_frame(
                    msg_type=int(followup.get("msg_type") or 0),
                    session_id=int(followup.get("session_id") or 0),
                    msg_id=int(followup.get("msg_id") or 0),
                    code=int(followup.get("code") or 0),
                    payload=payload_bytes,
                    cmd=int(followup.get("cmd") or 0),
                    code_endian=str(followup.get("code_endian") or "be"),
                )
                sent_summary = {
                    "msg_type": int(followup.get("msg_type") or 0),
                    "session_id": int(followup.get("session_id") or 0),
                    "msg_id": int(followup.get("msg_id") or 0),
                    "cmd": int(followup.get("cmd") or 0),
                    "code": int(followup.get("code") or 0),
                    "code_endian": str(followup.get("code_endian") or "be"),
                    "send_phase": str(followup.get("send_phase") or ""),
                    "controller_profile": str(followup.get("controller_profile") or ""),
                    "payload_len": len(payload_bytes),
                    "payload_head_hex": payload_bytes[:32].hex(),
                }
                try:
                    sock.sendall(followup_frame)
                except OSError as exc:
                    sent_summary["send_error"] = str(exc)
                    followup_send_error = dict(sent_summary)
                    sent_followups.append(sent_summary)
                    return False
                sent_followups.append(sent_summary)
                return True

            session_hex = _format_session_hex(session_int, width=session_hex_width)
            if initial_payload_text:
                payload_text = str(initial_payload_text).replace("{{SESSION_ID}}", session_hex)
                payload = payload_text.encode("utf-8", errors="ignore") + b"\x00"
            else:
                payload = build_plain_opmonitor_claim_payload(
                    session_int=session_int,
                    channel=channel,
                    stream_type=stream_type,
                    trans_mode=trans_mode,
                    combine_mode=combine_mode,
                    session_hex_width=session_hex_width,
                )
            frame = _build_tcp_frame(
                msg_type=0,
                session_id=session_int,
                msg_id=msg_id,
                code=int(initial_code if initial_code is not None else code),
                payload=payload,
                code_endian=code_endian,
            )
            sock.sendall(frame)

            buffer = leftover
            received = bytearray(leftover)
            frames: list[TcpFrame] = []
            data_frame_count = 0
            data_total_bytes = 0
            total_frame_count = 0
            first_frame_summaries: list[dict[str, Any]] = []
            data_frame_summaries: list[dict[str, Any]] = []
            callback_error = ""
            probe_started_at = time.time()
            end_time = probe_started_at + max(0.5, capture_seconds)
            first_data_frame_at = 0.0
            last_data_frame_at = 0.0
            last_chunk_at = 0.0
            exit_reason = ""
            pending_followups = [dict(item) for item in (followup_frames or [])]
            followup_delay_applied = False
            opmonitor_success_seen = False
            media_data_seen = False
            keepalive_sent: list[dict[str, Any]] = []
            next_keepalive_at = 0.0
            keepalive_msg_id = int(msg_id)
            keepalive_debug: dict[str, Any] = {
                "start_delay": float(keepalive_replay_start_delay),
                "interval": float(keepalive_replay_interval),
                "opmonitor_success_seen": False,
                "media_data_seen": False,
                "opmonitor_success_at": None,
                "first_media_at": None,
                "next_keepalive_at": None,
                "activation_reason": None,
                "loop_last_at": None,
            }

            def _is_media_payload_frame(frame: TcpFrame) -> bool:
                if int(frame.msg_type or 0) == 1:
                    return True
                if int(frame.cmd or 0) != 0x0584 or not frame.payload:
                    return False
                text = frame.payload[:16].decode("utf-8", errors="ignore").lstrip()
                return not text.startswith("{")

            def _arm_keepalive(now: float, reason: str) -> None:
                nonlocal next_keepalive_at
                if keepalive_replay_interval <= 0 or next_keepalive_at > 0:
                    return
                next_keepalive_at = now + max(1.0, float(keepalive_replay_start_delay))
                keepalive_debug["next_keepalive_at"] = next_keepalive_at
                keepalive_debug["activation_reason"] = reason

            def _maybe_send_keepalive(now: float) -> None:
                nonlocal keepalive_msg_id
                nonlocal next_keepalive_at
                keepalive_debug["loop_last_at"] = now
                keepalive_debug["opmonitor_success_seen"] = bool(opmonitor_success_seen)
                keepalive_debug["media_data_seen"] = bool(media_data_seen)
                keepalive_debug["next_keepalive_at"] = next_keepalive_at or None
                if (
                    keepalive_replay_interval <= 0
                    or not media_data_seen
                    or next_keepalive_at <= 0
                    or now < next_keepalive_at
                ):
                    return
                keepalive_msg_id += 1
                keepalive_payload_text = build_named_session_plaintext(
                    "KeepAlive",
                    session_id=session_int,
                    session_width=session_hex_width,
                )
                keepalive_payload = (
                    keepalive_payload_text.encode("utf-8", errors="ignore") + b"\x00"
                )
                keepalive_followup = {
                    "msg_type": 0,
                    "session_id": session_int,
                    "msg_id": keepalive_msg_id,
                    "cmd": 0x03EE,
                    "code": code,
                    "code_endian": code_endian,
                    "payload_bytes": keepalive_payload,
                    "send_phase": "plain_keepalive",
                    "controller_profile": "plain_keepalive",
                }
                if _send_followup_dict(keepalive_followup):
                    keepalive_sent.append(
                        {
                            "msg_id": keepalive_msg_id,
                            "sent_at": now,
                            "payload_len": len(keepalive_payload),
                            "payload_text": keepalive_payload_text,
                        }
                    )
                    next_keepalive_at = now + max(1.0, float(keepalive_replay_interval))
                    keepalive_debug["next_keepalive_at"] = next_keepalive_at

            while time.time() < end_time and total_frame_count < max_frames and not (stop_event is not None and stop_event.is_set()):
                now = time.time()
                _maybe_send_keepalive(now)
                timed_out = False
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    timed_out = True
                    chunk = b""
                if not chunk:
                    if pending_followups and (opmonitor_success_seen or media_data_seen):
                        pending_followups = []
                    if pending_followups and (frames or send_followups_on_silence):
                        if followup_delay > 0 and not followup_delay_applied:
                            time.sleep(followup_delay)
                            followup_delay_applied = True
                        sent_any = False
                        for followup in pending_followups:
                            frame_delay = float(followup.get("delay_before") or 0.0)
                            if frame_delay > 0:
                                time.sleep(frame_delay)
                            if not _send_followup_dict(followup):
                                end_time = time.time()
                                break
                            sent_any = True
                        pending_followups = []
                        if sent_any:
                            continue
                    if timed_out:
                        continue
                    exit_reason = "remote_closed"
                    break
                else:
                    last_chunk_at = time.time()
                    received.extend(chunk)
                    if extend_on_activity:
                        end_time = time.time() + max(0.5, capture_seconds)
                    buffer += chunk
                    parsed_frames, buffer = _parse_tcp_frames(buffer)
                    if parsed_frames:
                        for parsed_frame in parsed_frames:
                            total_frame_count += 1
                            if len(first_frame_summaries) < 5:
                                first_frame_summaries.append(parsed_frame.summary())
                            if _is_media_payload_frame(parsed_frame):
                                media_data_seen = True
                                data_now = time.time()
                                if first_data_frame_at <= 0:
                                    first_data_frame_at = data_now
                                last_data_frame_at = data_now
                                keepalive_debug["media_data_seen"] = True
                                if keepalive_debug.get("first_media_at") is None:
                                    first_media_now = time.time()
                                    keepalive_debug["first_media_at"] = first_media_now
                                    _arm_keepalive(first_media_now, "first_media")
                                data_frame_count += 1
                                data_total_bytes += len(parsed_frame.payload)
                                if len(data_frame_summaries) < MEDIA_FRAME_SUMMARY_LIMIT:
                                    data_frame_summaries.append(
                                        _summarize_tcp_frame(
                                            parsed_frame,
                                            include_payload_b64=(len(data_frame_summaries) < MEDIA_PAYLOAD_B64_LIMIT),
                                        )
                                    )
                                if on_data_frame_payload is not None:
                                    try:
                                        on_data_frame_payload(bytes(parsed_frame.payload), str(getattr(self, "vekey1", "") or ""))
                                    except Exception as exc:
                                        callback_error = f"{type(exc).__name__}: {exc}"
                                        exit_reason = "callback_error"
                                        end_time = time.time()
                                        if stop_event is not None:
                                            stop_event.set()
                                        break
                                continue
                            frames.append(parsed_frame)
                            if int(parsed_frame.msg_type or 0) != 0 or int(parsed_frame.cmd or 0) != 0x0586:
                                continue
                            payload_text = parsed_frame.payload.decode("utf-8", errors="ignore").strip("\x00\r\n ")
                            if not payload_text.startswith("{"):
                                continue
                            try:
                                payload_json = json.loads(payload_text)
                            except Exception:
                                payload_json = {}
                            if int(_intish(payload_json.get("Ret"), -1) or -1) == 100:
                                opmonitor_success_seen = True
                                keepalive_debug["opmonitor_success_seen"] = True
                                if keepalive_debug.get("opmonitor_success_at") is None:
                                    keepalive_debug["opmonitor_success_at"] = time.time()
                                if keepalive_replay_interval > 0:
                                    _arm_keepalive(time.time(), "opmonitor_success")
                                pending_followups = []
                        if not response_triggered and response_trigger_followups:
                            for parsed_frame in parsed_frames:
                                if int(parsed_frame.msg_type or 0) != 0 or int(parsed_frame.cmd or 0) != 0x0586:
                                    continue
                                payload_text = parsed_frame.payload.decode("utf-8", errors="ignore").strip("\x00\r\n ")
                                if not payload_text.startswith("{"):
                                    continue
                                try:
                                    payload_json = json.loads(payload_text)
                                except Exception:
                                    payload_json = {}
                                if int(_intish(payload_json.get("Ret"), -1) or -1) == 103:
                                    pending_followups.extend([dict(item) for item in response_trigger_followups])
                                    response_triggered = True
                                    break
                        if callback_error:
                            break
                if pending_followups and (opmonitor_success_seen or media_data_seen):
                    pending_followups = []
                if pending_followups and total_frame_count > 0:
                    if followup_delay > 0 and not followup_delay_applied:
                        time.sleep(followup_delay)
                        followup_delay_applied = True
                    for followup in pending_followups:
                        frame_delay = float(followup.get("delay_before") or 0.0)
                        if frame_delay > 0:
                            time.sleep(frame_delay)
                        if not _send_followup_dict(followup):
                            end_time = time.time()
                        break
                    pending_followups = []

            if not exit_reason:
                if stop_event is not None and stop_event.is_set():
                    exit_reason = "cancelled"
                elif total_frame_count >= max_frames:
                    exit_reason = "max_frames"
                elif time.time() >= end_time:
                    exit_reason = "idle_timeout"
                else:
                    exit_reason = "loop_exit"

            control_frames = [f for f in frames if f.msg_type == 0]
            opmonitor_resp: dict[str, Any] = {}
            for frame_item in control_frames:
                text = frame_item.payload.decode("utf-8", errors="ignore").strip("\x00\r\n ")
                if text.startswith("{"):
                    try:
                        opmonitor_resp = json.loads(text)
                        break
                    except Exception:
                        continue

            result["opmonitor"] = {
                "sent": {
                    "session_id": session_int,
                    "session_hex": session_hex,
                    "msg_id": msg_id,
                    "code": code,
                    "code_endian": code_endian,
                    "payload_len": len(payload),
                },
                "response": opmonitor_resp,
            }
            if sent_followups:
                result["opmonitor"]["followups"] = sent_followups
            if followup_send_error:
                result["opmonitor"]["followup_send_error"] = followup_send_error
            if keepalive_sent:
                result["opmonitor"]["keepalives"] = keepalive_sent
            if keepalive_replay_interval > 0:
                result["opmonitor"]["keepalive_debug"] = keepalive_debug
            result["frames"] = {
                "total": total_frame_count,
                "control": len(control_frames),
                "data": data_frame_count,
                "data_total_bytes": data_total_bytes,
                "exit_reason": exit_reason,
                "duration_seconds": round(time.time() - probe_started_at, 3),
                "media_span_seconds": round(last_data_frame_at - first_data_frame_at, 3) if first_data_frame_at and last_data_frame_at else 0.0,
                "first_data_at_seconds": round(first_data_frame_at - probe_started_at, 3) if first_data_frame_at else None,
                "last_data_at_seconds": round(last_data_frame_at - probe_started_at, 3) if last_data_frame_at else None,
                "last_chunk_at_seconds": round(last_chunk_at - probe_started_at, 3) if last_chunk_at else None,
                "first_frames": first_frame_summaries,
                "data_frames": data_frame_summaries,
                "raw_total_bytes": len(received),
                "raw_head_hex": bytes(received[:128]).hex(),
                "raw_tail_hex": bytes(buffer[:128]).hex(),
            }
            result["local_bootstrap_summary"] = analyze_local_media_bootstrap_frames(
                data_frame_summaries,
                media_random_str=media_random_str,
                vekey1=str(getattr(self, "vekey1", "") or ""),
                controller_status=_classify_media_control_ret(_intish(opmonitor_resp.get("Ret"), None)),
            )
            if opmonitor_resp.get("Ret") == 100 and data_frame_count > 0:
                result["status"] = "ok"
            else:
                result["status"] = "partial"
            if callback_error:
                result["error"] = callback_error
            return result
        finally:
            sock.close()


AgentTcpLiveProbe.run_probe = run_probe


class LocalAgentTcpBindProxy:
    def __init__(
        self,
        *,
        upstream_host: str,
        upstream_port: int,
        authcode: str,
        client_token: str,
        serial: str,
        session: str,
        random_str: str = "",
        timeout: float = 10.0,
        suffix: bytes = TCP_HANDSHAKE_SUFFIX,
    ) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = int(upstream_port)
        self.authcode = authcode
        self.client_token = client_token
        self.serial = serial
        self.session = session
        self.random_str = random_str
        self.timeout = float(timeout)
        self.suffix = suffix
        self.local_host = "127.0.0.1"
        self.local_port = 0
        self.listener: socket.socket | None = None
        self.downstream: socket.socket | None = None
        self.upstream: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.accepted_event = threading.Event()
        self.ready_event = threading.Event()
        self.state = "init"
        self.error = ""
        self.handshake: dict[str, Any] = {}
        self.counters: dict[str, int] = {
            "downstream_to_upstream_bytes": 0,
            "upstream_to_downstream_bytes": 0,
        }
        self.timeline: dict[str, float] = {
            "created_at": time.time(),
        }

    def start(self) -> dict[str, Any]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.local_host, 0))
        listener.listen(1)
        listener.settimeout(0.2)
        self.listener = listener
        self.local_port = int(listener.getsockname()[1])
        self.timeline["listener_ready_at"] = time.time()
        self.thread = threading.Thread(target=self._run, name="icsee-local-agent-bind", daemon=True)
        self.thread.start()
        self.timeline["thread_started_at"] = time.time()
        self.state = "listening"
        return self.summary()

    def summary(self) -> dict[str, Any]:
        created_at = float(self.timeline.get("created_at") or 0.0)
        timing: dict[str, float] = {}
        if created_at > 0:
            for key, value in self.timeline.items():
                if key == "created_at":
                    continue
                if isinstance(value, (int, float)) and value > 0:
                    timing[f"{key}_delta"] = round(float(value) - created_at, 6)
        return {
            "status": self.state,
            "local_host": self.local_host,
            "local_port": self.local_port,
            "upstream_host": self.upstream_host,
            "upstream_port": self.upstream_port,
            "random_str": self.random_str or None,
            "accepted": self.accepted_event.is_set(),
            "ready": self.ready_event.is_set(),
            "handshake": self.handshake,
            "counters": dict(self.counters),
            "timeline": dict(self.timeline),
            "timing": timing,
            "error": self.error or None,
        }

    def close(self) -> None:
        self.stop_event.set()
        for sock_obj in (self.listener, self.downstream, self.upstream):
            if sock_obj is None:
                continue
            try:
                sock_obj.close()
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=2.0)

    def _close_socket(self, sock_obj: socket.socket | None) -> None:
        if sock_obj is None:
            return
        try:
            sock_obj.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock_obj.close()
        except OSError:
            pass

    def _run(self) -> None:
        try:
            if self.listener is None:
                self.state = "error"
                self.error = "listener_not_started"
                return
            self.timeline["accept_wait_started_at"] = time.time()
            while not self.stop_event.is_set():
                try:
                    downstream, _addr = self.listener.accept()
                    self.downstream = downstream
                    self.timeline["accepted_at"] = time.time()
                    break
                except socket.timeout:
                    continue
            if self.downstream is None:
                self.state = "stopped"
                return
            self.accepted_event.set()
            self.state = "accepted"
            self.downstream.settimeout(self.timeout)

            self.timeline["upstream_connect_started_at"] = time.time()
            self.upstream = _create_tcp_connection((self.upstream_host, self.upstream_port), timeout=self.timeout)
            self.upstream.settimeout(self.timeout)
            self.timeline["upstream_connected_at"] = time.time()
            self.state = "upstream_connected"

            handshake_b64 = AgentTcpLiveProbe(self.suffix).build_handshake(
                self.authcode,
                self.client_token,
                self.serial,
                self.session,
            )
            handshake_text = f"{self.authcode}:{self.client_token}:{self.serial}:{self.session}"
            self.handshake = {
                "sent_b64": handshake_b64.decode("ascii", errors="ignore"),
                "sent_text": handshake_text,
                "sent_wire_text": _format_handshake_wire_text(handshake_text, self.suffix),
                "sent_suffix_hex": self.suffix.hex(),
            }
            self.timeline["handshake_sent_at"] = time.time()
            self.upstream.sendall(handshake_b64)
            b64_resp, _leftover, err = _recv_base64_message(self.upstream, timeout=self.timeout, suffix=self.suffix)
            if not b64_resp:
                self.state = "error"
                self.error = err or "upstream_handshake_no_response"
                self.handshake = {**self.handshake, "ok": False, "error": self.error}
                return
            decoded, dec_err = _decode_base64_with_suffix(b64_resp, self.suffix)
            if decoded is None:
                self.state = "error"
                self.error = dec_err or "upstream_handshake_decode_failed"
                self.handshake = {**self.handshake, "ok": False, "error": self.error}
                return
            parsed = AgentTcpLiveProbe(self.suffix).parse_handshake_response(decoded)
            self.handshake = {
                **self.handshake,
                "ok": True,
                "b64_len": len(b64_resp),
                "decoded_len": len(decoded),
                "parsed": parsed,
                **_summarize_handshake_reply(b64_resp, parsed),
            }
            self.timeline["handshake_reply_at"] = time.time()
            self.state = "running"
            self.ready_event.set()
            self.timeline["relay_loop_started_at"] = time.time()
            self._relay_loop()
            if self.state != "error":
                self.state = "closed"
        except Exception as exc:  # noqa: BLE001
            self.state = "error"
            self.error = str(exc)
        finally:
            self.timeline["closed_at"] = time.time()
            self._close_socket(self.downstream)
            self._close_socket(self.upstream)
            self._close_socket(self.listener)

    def _relay_loop(self) -> None:
        if self.downstream is None or self.upstream is None:
            self.state = "error"
            self.error = "relay_missing_socket"
            return
        downstream = self.downstream
        upstream = self.upstream
        tx_cipher = _XorKeystream(self.random_str) if self.random_str else None
        rx_cipher = _XorKeystream(self.random_str) if self.random_str else None
        while not self.stop_event.is_set():
            readable, _w, _x = select.select([downstream, upstream], [], [], 0.1)
            if not readable:
                continue
            if downstream in readable:
                chunk = downstream.recv(8192)
                if not chunk:
                    break
                if tx_cipher is not None:
                    chunk = tx_cipher.apply(chunk)
                upstream.sendall(chunk)
                self.counters["downstream_to_upstream_bytes"] += len(chunk)
            if upstream in readable:
                chunk = upstream.recv(8192)
                if not chunk:
                    break
                if rx_cipher is not None:
                    chunk = rx_cipher.apply(chunk)
                downstream.sendall(chunk)
                self.counters["upstream_to_downstream_bytes"] += len(chunk)


class LocalAgentSdkBindProxy:
    def __init__(
        self,
        *,
        access_host: str,
        access_port: int,
        authcode: str,
        serial: str,
        dest_port: str,
        service_type: str,
        encrypt: str = "1",
        step: str = "",
        protocol_mode: str = "tcp",
        vendor: str = "",
        developer_id: str = "",
        app_key: str = "",
        timeout: float = 10.0,
        user_agent: str = DEFAULT_STATUS_UA,
        content_type: str = "text/html",
        ssl_verify: bool = False,
        suffix: bytes = TCP_HANDSHAKE_SUFFIX,
        agent_client_uuid: str = "",
        agent_session_id: str = "",
        prime_selector_early: bool = False,
        access_urls: list[str] | None = None,
        content_types: list[str] | None = None,
    ) -> None:
        self.access_host = access_host
        self.access_port = int(access_port)
        self.authcode = authcode
        self.serial = serial
        self.dest_port = str(dest_port)
        self.service_type = str(service_type)
        self.encrypt = str(encrypt or "1")
        self.step = str(step or ("0" if self.service_type == "RpsCmd" else "8"))
        self.protocol_mode = str(protocol_mode or "tcp")
        self.vendor = str(vendor or "")
        self.developer_id = str(developer_id or "")
        self.app_key = str(app_key or "")
        self.timeout = float(timeout)
        self.user_agent = str(user_agent or DEFAULT_STATUS_UA)
        self.base_content_type = str(content_type or "text/html")
        self.ssl_verify = bool(ssl_verify)
        self.suffix = suffix
        self.local_host = "127.0.0.1"
        self.local_port = 0
        self.listener: socket.socket | None = None
        self.downstream: socket.socket | None = None
        self.upstream: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.accepted_event = threading.Event()
        self.ready_event = threading.Event()
        self.state = "init"
        self.error = ""
        self.handshake: dict[str, Any] = {}
        self.access_attempts: list[dict[str, Any]] = []
        self.selected_access: dict[str, Any] = {}
        self.agent_server: dict[str, Any] = {}
        self.counters: dict[str, int] = {
            "downstream_to_upstream_bytes": 0,
            "upstream_to_downstream_bytes": 0,
        }
        self.agent_client_uuid = str(agent_client_uuid or "").strip() or get_agent_client_uuid()
        self.agent_session_id = str(agent_session_id or "").strip()
        default_urls = [
            f"https://{self.access_host}:{self.access_port}/",
        ]
        self.access_urls = _dedupe([str(item) for item in (access_urls or default_urls) if str(item).strip()])
        self.content_types = _dedupe(
            [str(item) for item in (content_types or [self.base_content_type, "text/html", "application/json"]) if str(item).strip()]
        )
        self.prime_selector_early = bool(prime_selector_early)

    def start(self) -> dict[str, Any]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.local_host, 0))
        listener.listen(1)
        listener.settimeout(0.2)
        self.listener = listener
        self.local_port = int(listener.getsockname()[1])
        self.thread = threading.Thread(target=self._run, name="icsee-sdk-agent-bind", daemon=True)
        self.thread.start()
        self.state = "listening"
        return self.summary()

    def summary(self) -> dict[str, Any]:
        return {
            "status": self.state,
            "mode": "sdk_bind_proxy",
            "local_host": self.local_host,
            "local_port": self.local_port,
            "access_host": self.access_host,
            "access_port": self.access_port,
            "service_type": self.service_type,
            "step": self.step,
            "dest_port": self.dest_port,
            "developer_id": self.developer_id or None,
            "app_key_masked": _mask_secret(self.app_key, 6, 4) if self.app_key else None,
            "agent_client_uuid_masked": _mask_secret(self.agent_client_uuid, 8, 4),
            "agent_session_id_masked": _mask_secret(self.agent_session_id, 6, 4),
            "prime_selector_early": self.prime_selector_early,
            "selected_access": dict(self.selected_access),
            "agent_server": dict(self.agent_server),
            "accepted": self.accepted_event.is_set(),
            "ready": self.ready_event.is_set(),
            "handshake": self.handshake,
            "access_attempts": list(self.access_attempts),
            "counters": dict(self.counters),
            "error": self.error or None,
        }

    def close(self) -> None:
        self.stop_event.set()
        for sock_obj in (self.listener, self.downstream, self.upstream):
            if sock_obj is None:
                continue
            try:
                sock_obj.close()
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=2.0)

    def _close_socket(self, sock_obj: socket.socket | None) -> None:
        if sock_obj is None:
            return
        try:
            sock_obj.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock_obj.close()
        except OSError:
            pass

    def _select_agent_server(self) -> dict[str, Any]:
        attempts, selected, agent_server = select_agent_server_via_query(
            authcode=self.authcode,
            serial=self.serial,
            client_token=self.agent_client_uuid,
            dest_port=self.dest_port,
            service_type=self.service_type,
            session_id=self.agent_session_id,
            encrypt=self.encrypt,
            step=self.step,
            protocol_mode=self.protocol_mode,
            vendor=self.vendor,
            access_urls=self.access_urls,
            content_types=self.content_types,
            timeout=max(1, int(self.timeout)),
            ssl_verify=self.ssl_verify,
            user_agent=self.user_agent,
        )
        self.access_attempts.extend(attempts)
        if selected:
            self.selected_access = dict(selected)
        if agent_server:
            self.agent_server = dict(agent_server)
            return self.agent_server
        return {}

    def _build_upstream_handshake(self) -> bytes:
        # Successful phone captures for both control and media 6611 flows use the
        # 4-part handshake only: authcode:client_token:serial:session.
        # Adding developer/app-key here makes the bind proxy diverge from the
        # actual app traffic and has correlated with "dead" 6611 sessions that
        # never return the base64 DestIP reply.
        raw_text = f"{self.authcode}:{self.agent_client_uuid}:{self.serial}:{self.agent_session_id}"
        raw = raw_text.encode("utf-8") + self.suffix
        return base64.b64encode(raw)

    def _run(self) -> None:
        try:
            if self.listener is None:
                self.state = "error"
                self.error = "listener_not_started"
                return
            if self.prime_selector_early:
                if not self.agent_session_id:
                    self.agent_session_id = build_session_id()
                if not self.agent_server:
                    self.state = "selecting_access"
                    self._select_agent_server()
                    if self.agent_server:
                        self.state = "listening"
            while not self.stop_event.is_set():
                try:
                    downstream, _addr = self.listener.accept()
                    self.downstream = downstream
                    break
                except socket.timeout:
                    continue
            if self.downstream is None:
                self.state = "stopped"
                return
            self.accepted_event.set()
            self.state = "accepted"
            self.downstream.settimeout(self.timeout)

            if not self.agent_session_id:
                self.agent_session_id = build_session_id()
            selected = dict(self.agent_server)
            if not selected:
                self.state = "selecting_access"
                selected = self._select_agent_server()
            if not selected.get("ip") or not int(selected.get("port") or 0):
                self.state = "error"
                self.error = "agent_access_no_response"
                return

            self.upstream = _create_tcp_connection((str(selected.get("ip")), int(selected.get("port") or 0)), timeout=self.timeout)
            self.upstream.settimeout(self.timeout)
            self.state = "upstream_connected"

            handshake_b64 = self._build_upstream_handshake()
            handshake_text = f"{self.authcode}:{self.agent_client_uuid}:{self.serial}:{self.agent_session_id}"
            self.handshake = {
                "sent_b64": handshake_b64.decode("ascii", errors="ignore"),
                "sent_text": handshake_text,
                "sent_wire_text": _format_handshake_wire_text(handshake_text, self.suffix),
                "sent_suffix_hex": self.suffix.hex(),
            }
            self.upstream.sendall(handshake_b64)
            b64_resp, _leftover, err = _recv_base64_message(self.upstream, timeout=self.timeout, suffix=self.suffix)
            if not b64_resp:
                self.state = "error"
                self.error = err or "upstream_handshake_no_response"
                self.handshake = {**self.handshake, "ok": False, "error": self.error}
                return
            decoded, dec_err = _decode_base64_with_suffix(b64_resp, self.suffix)
            if decoded is None:
                self.state = "error"
                self.error = dec_err or "upstream_handshake_decode_failed"
                self.handshake = {**self.handshake, "ok": False, "error": self.error}
                return
            parsed = AgentTcpLiveProbe(self.suffix).parse_handshake_response(decoded)
            self.handshake = {
                **self.handshake,
                "ok": True,
                "b64_len": len(b64_resp),
                "decoded_len": len(decoded),
                "parsed": parsed,
                **_summarize_handshake_reply(b64_resp, parsed),
            }
            self.state = "running"
            self.ready_event.set()
            self._relay_loop()
            if self.state != "error":
                self.state = "closed"
        except Exception as exc:  # noqa: BLE001
            self.state = "error"
            self.error = str(exc)
        finally:
            self._close_socket(self.downstream)
            self._close_socket(self.upstream)
            self._close_socket(self.listener)

    def _relay_loop(self) -> None:
        if self.downstream is None or self.upstream is None:
            self.state = "error"
            self.error = "relay_missing_socket"
            return
        downstream = self.downstream
        upstream = self.upstream
        random_str = str(self.agent_server.get("random_str") or "")
        tx_cipher = _XorKeystream(random_str) if random_str else None
        rx_cipher = _XorKeystream(random_str) if random_str else None
        while not self.stop_event.is_set():
            readable, _w, _x = select.select([downstream, upstream], [], [], 0.1)
            if not readable:
                continue
            if downstream in readable:
                chunk = downstream.recv(8192)
                if not chunk:
                    break
                if tx_cipher is not None:
                    chunk = tx_cipher.apply(chunk)
                upstream.sendall(chunk)
                self.counters["downstream_to_upstream_bytes"] += len(chunk)
            if upstream in readable:
                chunk = upstream.recv(8192)
                if not chunk:
                    break
                if rx_cipher is not None:
                    chunk = rx_cipher.apply(chunk)
                downstream.sendall(chunk)
                self.counters["upstream_to_downstream_bytes"] += len(chunk)


def run_local_agent_live_probe(
    *,
    upstream_host: str,
    upstream_port: int,
    authcode: str,
    client_token: str,
    serial: str,
    session: str,
    session_int: int,
    channel: int,
    stream_type: str,
    trans_mode: str,
    combine_mode: str,
    msg_id: int,
    code: int,
    code_endian: str,
    timeout: float,
    capture_seconds: float,
    max_frames: int,
    random_str: str = "",
    media_random_str: str = "",
    vekey1: str = "",
    followup_frames: list[dict[str, Any]] | None = None,
    followup_delay: float = 0.0,
    initial_payload_text: str = "",
    initial_code: int | None = None,
    on_data_frame_payload: Callable[[bytes, str], None] | None = None,
    stop_event: threading.Event | None = None,
    extend_on_activity: bool = False,
) -> dict[str, Any]:
    bind_proxy = LocalAgentTcpBindProxy(
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        authcode=authcode,
        client_token=client_token,
        serial=serial,
        session=session,
        random_str=random_str,
        timeout=timeout,
    )
    bind_proxy.start()
    try:
        return run_prebound_local_agent_live_probe(
            bind_proxy=bind_proxy,
            authcode=authcode,
            client_token=client_token,
            serial=serial,
            session=session,
            session_int=session_int,
            channel=channel,
            stream_type=stream_type,
            trans_mode=trans_mode,
            combine_mode=combine_mode,
            msg_id=msg_id,
            code=code,
            code_endian=code_endian,
            timeout=timeout,
            capture_seconds=capture_seconds,
            max_frames=max_frames,
            media_random_str=media_random_str,
            vekey1=vekey1,
            followup_frames=followup_frames,
            followup_delay=followup_delay,
            initial_payload_text=initial_payload_text,
            initial_code=initial_code,
            on_data_frame_payload=on_data_frame_payload,
            stop_event=stop_event,
            extend_on_activity=extend_on_activity,
        )
    finally:
        bind_proxy.close()


def run_prebound_local_agent_live_probe(
    *,
    bind_proxy: LocalAgentTcpBindProxy | LocalAgentSdkBindProxy,
    authcode: str,
    client_token: str,
    serial: str,
    session: str,
    session_int: int,
    channel: int,
    stream_type: str,
    trans_mode: str,
    combine_mode: str,
    msg_id: int,
    code: int,
    code_endian: str,
    timeout: float,
    capture_seconds: float,
    max_frames: int,
    media_random_str: str = "",
    vekey1: str = "",
    followup_frames: list[dict[str, Any]] | None = None,
    followup_delay: float = 0.0,
    initial_payload_text: str = "",
    initial_code: int | None = None,
    on_data_frame_payload: Callable[[bytes, str], None] | None = None,
    stop_event: threading.Event | None = None,
    extend_on_activity: bool = False,
) -> dict[str, Any]:
    probe = AgentTcpLiveProbe()
    probe.vekey1 = str(vekey1 or "")
    response_trigger_followups = None
    keepalive_replay_start_delay = 0.0
    keepalive_replay_interval = 0.0
    if isinstance(bind_proxy, LocalAgentSdkBindProxy):
        response_trigger_followups = build_plain_claim_replay_followups(
            session_int=session_int,
            channel=channel,
            stream_type=stream_type,
            trans_mode=trans_mode,
            combine_mode=combine_mode,
            msg_id=msg_id + max(0, len(followup_frames or [])),
            code=code,
            code_endian=code_endian,
            replay_count=3,
            first_delay=0.7,
            delay_step=0.8,
            msg_id_step=1,
        )
    elif isinstance(bind_proxy, LocalAgentTcpBindProxy):
        # Reference live traces keep the plain second-6611 alive with
        # periodic KeepAlive frames, not repeated OPMonitor Start.
        # Typical cadence is about 15 seconds, with the first KeepAlive
        # arriving roughly 12-15 seconds after OPMonitor Ret=100.
        keepalive_replay_start_delay = 12.0
        keepalive_replay_interval = 15.0
    result = probe.run_probe(
        host=bind_proxy.local_host,
        port=bind_proxy.local_port,
        authcode=authcode,
        client_token=client_token,
        serial=serial,
        session=session,
        session_int=session_int,
        channel=channel,
        stream_type=stream_type,
        trans_mode=trans_mode,
        combine_mode=combine_mode,
        msg_id=msg_id,
        code=code,
        code_endian=code_endian,
        timeout=timeout,
        capture_seconds=capture_seconds,
        max_frames=max_frames,
        media_random_str=media_random_str,
        followup_frames=followup_frames,
        followup_delay=followup_delay,
        initial_payload_text=initial_payload_text,
        initial_code=initial_code,
        skip_handshake=True,
        ready_event=bind_proxy.ready_event if isinstance(bind_proxy, LocalAgentSdkBindProxy) else None,
        ready_timeout=min(max(0.5, timeout), 8.0) if isinstance(bind_proxy, LocalAgentSdkBindProxy) else 0.0,
        send_followups_on_silence=isinstance(bind_proxy, LocalAgentSdkBindProxy),
        response_trigger_followups=response_trigger_followups,
        on_data_frame_payload=on_data_frame_payload,
        stop_event=stop_event,
        extend_on_activity=extend_on_activity,
        keepalive_replay_start_delay=keepalive_replay_start_delay,
        keepalive_replay_interval=keepalive_replay_interval,
    )
    result["agent_bind"] = bind_proxy.summary()
    return result


class AgentTcpEncryptedClaimProbe:
    def __init__(self, suffix: bytes = TCP_HANDSHAKE_SUFFIX) -> None:
        self.suffix = suffix

    def build_handshake(self, authcode: str, client_token: str, serial: str, session: str) -> bytes:
        raw = f"{authcode}:{client_token}:{serial}:{session}".encode("utf-8") + self.suffix
        return base64.b64encode(raw)

    def parse_handshake_response(self, decoded: bytes) -> dict[str, Any]:
        if decoded.endswith(self.suffix):
            decoded = decoded[: -len(self.suffix)]
        text = decoded.decode("utf-8", errors="replace")
        try:
            json_data = json.loads(text)
        except Exception:
            json_data = None
        return {
            "text": text,
            "json": json_data,
        }

    def run_probe(
        self,
        *,
        host: str,
        port: int,
        authcode: str,
        client_token: str,
        serial: str,
        session: str,
        xor_key: str,
        claim_random_a: str,
        session_int: int,
        channel: int,
        stream_type: str,
        trans_mode: str,
        combine_mode: str,
        msg_id: int,
        unk: int,
        cmd: int,
        timeout: float,
        capture_seconds: float,
        max_frames: int,
        session_hex_width: int = 10,
        followup_frames: list[dict[str, Any]] | None = None,
        followup_delay: float = 0.0,
        login_followup_builder: dict[str, Any] | None = None,
        controller_auto: bool = False,
        controller_profile: str = "historical_order_built_queries_dynamic_second582",
        plain_handoff_config: dict[str, Any] | None = None,
        skip_handshake: bool = False,
        stop_event: threading.Event | None = None,
        plain_handoff_data_frame_callback: Callable[[bytes, str], None] | None = None,
        plain_handoff_extend_on_activity: bool = False,
        dynamic_followup_queue: Any | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "error",
            "agent_host": host,
            "agent_port": port,
            "handshake": {},
            "claim": {},
            "frames": {},
            "plain_handoff_runs": [],
            "plain_handoff_agent_http": {},
            "plain_handoff_agent_server": {},
            "plain_handoff_probe": {},
            "plain_handoff_timeline": [],
        }
        probe_started_at = time.time()

        def _emit_progress(detail: str) -> None:
            if progress_callback is not None:
                progress_callback(" ".join(str(detail or "").split()))

        def _tcp_progress_payload(summary: dict[str, Any]) -> str:
            payload_json = _frame_json_payload(summary)
            parts = [
                f"cmd=0x{int(summary.get('cmd') or 0):04x}",
                f"msg={int(summary.get('msg_id') or 0)}",
            ]
            if "Ret" in payload_json:
                parts.append(f"Ret={payload_json.get('Ret')}")
            payload_len = int(summary.get("payload_len") or 0)
            if payload_len:
                parts.append(f"bytes={payload_len}")
            stage = _controller_stage_name(int(summary.get("cmd") or 0))
            if stage:
                parts.append(stage)
            return " ".join(parts)

        def _record_plain_handoff_event(event: str, **extra: Any) -> None:
            entry: dict[str, Any] = {
                "event": event,
                "t_rel": round(time.time() - probe_started_at, 6),
            }
            for key, value in extra.items():
                if value is not None:
                    entry[key] = value
            result["plain_handoff_timeline"].append(entry)

        tx_cipher = _XorKeystream(xor_key)
        rx_cipher = _XorKeystream(xor_key)
        _emit_progress(f"TCP connect request {host}:{port}")
        sock = _create_tcp_connection((host, port), timeout=timeout)
        _emit_progress(f"TCP connect response {host}:{port}")
        sock.settimeout(min(float(timeout), 0.2 if dynamic_followup_queue is not None else 1.0))
        try:
            leftover = b""
            if skip_handshake:
                result["handshake"] = {
                    "ok": True,
                    "skipped": True,
                    "mode": "local_bind_proxy",
                }
                _emit_progress("TCP 6611 handshake response skipped")
            else:
                handshake_timeout_raw = str(os.environ.get("ICSEE_FIRST6611_HANDSHAKE_TIMEOUT") or "").strip()
                try:
                    handshake_timeout = float(handshake_timeout_raw) if handshake_timeout_raw else min(float(timeout), 2.0)
                except ValueError:
                    handshake_timeout = min(float(timeout), 2.0)
                handshake_timeout = max(0.5, min(float(timeout), handshake_timeout))
                handshake_b64 = self.build_handshake(authcode, client_token, serial, session)
                handshake_text = f"{authcode}:{client_token}:{serial}:{session}"
                sent_info = {
                    "sent_b64": handshake_b64.decode("ascii", errors="ignore"),
                    "sent_text": handshake_text,
                    "sent_wire_text": _format_handshake_wire_text(handshake_text, self.suffix),
                    "sent_suffix_hex": self.suffix.hex(),
                    "timeout_seconds": handshake_timeout,
                }
                result["handshake"].update(sent_info)
                _emit_progress("TCP 6611 handshake request")
                sock.sendall(handshake_b64)
                b64_resp, leftover, err = _recv_base64_message(sock, timeout=handshake_timeout, suffix=self.suffix)
                if not b64_resp:
                    _emit_progress(f"TCP 6611 handshake response failed {err or 'no_response'}")
                    result["handshake"] = {
                        **sent_info,
                        "ok": False,
                        "error": err or "no_response",
                    }
                    return result
                decoded, dec_err = _decode_base64_with_suffix(b64_resp, self.suffix)
                if decoded is None:
                    _emit_progress(f"TCP 6611 handshake response decode failed {dec_err or 'decode_failed'}")
                    result["handshake"] = {
                        **sent_info,
                        "ok": False,
                        "error": dec_err or "decode_failed",
                    }
                    return result
                parsed = self.parse_handshake_response(decoded)
                result["handshake"] = {
                    **sent_info,
                    "ok": True,
                    "b64_len": len(b64_resp),
                    "decoded_len": len(decoded),
                    "parsed": parsed,
                    **_summarize_handshake_reply(b64_resp, parsed),
                }
                _emit_progress(f"TCP 6611 handshake response {len(b64_resp)} bytes")

            session_hex = _format_session_hex(session_int, width=session_hex_width)
            payload_obj = {
                "Name": "OPMonitor",
                "OPMonitor": {
                    "Action": "Claim",
                    "Parameter": {
                        "Channel": int(channel),
                        "CombinMode": combine_mode,
                        "StreamType": stream_type,
                        "TransMode": trans_mode,
                    },
                },
                "DHParameter": {"RandomStrA": claim_random_a},
                "SessionID": session_hex,
            }
            payload = json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\x00"
            frame = _build_tcp_frame(
                msg_type=0,
                session_id=session_int,
                msg_id=msg_id,
                code=0,
                payload=payload,
                unk=unk,
                cmd=cmd,
            )
            encrypted_frame = tx_cipher.apply(frame)
            _emit_progress(f"TCP OPMonitor Claim request cmd=0x{cmd:04x}")
            sock.sendall(encrypted_frame)

            buffer = rx_cipher.apply(leftover)
            received = bytearray(leftover)
            decoded_stream = bytearray(buffer)
            frames: list[TcpFrame] = []
            sent_followups: list[dict[str, Any]] = []
            initial_followup_frames = [dict(item) for item in (followup_frames or [])]
            stop_after_response_cmds = {
                int(item.get("stop_after_response_cmd") or 0)
                for item in initial_followup_frames
                if int(item.get("stop_after_response_cmd") or 0) > 0
            }
            pre_login_followup_templates: list[dict[str, Any]] = []
            post_login_followup_templates: list[dict[str, Any]] = []
            if login_followup_builder:
                followup_frames = []
                for template in initial_followup_frames:
                    phase = str(template.get("send_phase") or "post_login").strip().lower()
                    if phase in {"pre_login", "login"}:
                        pre_login_followup_templates.append(template)
                    else:
                        post_login_followup_templates.append(template)
            else:
                followup_frames = initial_followup_frames
            built_login_summary: dict[str, Any] = {}
            current_dataenc_key = ""
            current_media_random_str = ""
            current_vekey1 = ""
            current_not_encrypt_cmds: set[int] = set()
            login_followup_done = False
            login_followup_cmd = 0x03E8
            login_followup_msg_id = 0
            post_login_followups_queued = False
            auto_controller_enqueued = False
            runtime_session_id_live = 0
            login_success_seen_at = 0.0
            controller_response_seen_at = 0.0
            controller_ret_latest: int | None = None
            followup_wait_response_counts: Counter[int] = Counter()
            followup_wait_response_rets: dict[int, int | None] = {}
            followup_wait_response_cmds = {
                int(item.get("wait_for_response_cmd") or 0)
                for item in initial_followup_frames
                if int(item.get("wait_for_response_cmd") or 0) > 0
            }
            recv_error = ""
            auto_retry_582_done = False
            auto_retry_second582_done = False
            auto_retry_61a_done = False
            controller_pending_seen = False
            controller_readying_seen = False
            late_064d_after_readying_seen = False
            followup_schedule_started_at = 0.0
            followup_next_due_at = 0.0
            audio_support_413_seen = 0
            third_413_seen_at = 0.0
            post582_0551_seen = 0
            post582_064b_seen = 0
            post582_03fd_seen = False
            second_success_replay_state = "init"
            second_success_replay_seen_at = 0.0
            saw_data_frame = False
            plain_handoff_started = False
            plain_handoff_pending = False
            plain_handoff_thread: threading.Thread | None = None
            plain_handoff_join_timeout = 0.0
            plain_handoff_async_result: dict[str, Any] = {}
            plain_handoff_live_data_seen = threading.Event()
            followup_send_error: dict[str, Any] | None = None
            plain_handoff_trigger = str((plain_handoff_config or {}).get("start_trigger") or "after_second_413").strip().lower()
            plain_handoff_prepare_early = bool((plain_handoff_config or {}).get("prepare_early", True))
            plain_handoff_recreate_bind_on_start = bool(
                (plain_handoff_config or {}).get(
                    "recreate_bind_on_start",
                    plain_handoff_trigger == "after_second_success_replay",
                )
            )
            prebound_plain_bind_proxy: LocalAgentTcpBindProxy | LocalAgentSdkBindProxy | None = None
            prebound_plain_handoff_info: dict[str, Any] = {}
            response_gated_followups = bool(
                plain_handoff_config
                and controller_profile == "app_reference_first_6611"
                and plain_handoff_trigger == "after_second_413"
                and str(os.environ.get("ICSEE_RESPONSE_GATED_FIRST6611") or "").strip() == "1"
            )
            response_gated_followups_started = False
            response_gated_followups_release_pending = False
            response_drain_seconds = max(2.0, min(8.0, float(capture_seconds) * 0.35))
            controller_keepalive_interval = 30.0 if controller_profile == "app_reference_first_6611" else 0.0
            controller_keepalive_grace = max(5.0, min(12.0, response_drain_seconds + 4.0))
            controller_keepalive_next_at = 0.0
            controller_keepalive_sent = 0
            plain_handoff_prepare_stage = str((plain_handoff_config or {}).get("prepare_stage") or "after_login").strip().lower()
            dynamic_followup_frames: list[dict[str, Any]] = []
            dynamic_followup_msg_id = 0
            dynamic_followups_enqueued = 0
            dynamic_followups_sent = 0

            def _prepare_plain_handoff_bind() -> dict[str, Any]:
                if not plain_handoff_config:
                    return {}
                server_ip = str(plain_handoff_config.get("status_server_ip") or "").strip()
                server_port = str(plain_handoff_config.get("status_server_port") or "").strip()
                if not server_ip or not server_port:
                    return {}
                user_agent = str(plain_handoff_config.get("user_agent") or DEFAULT_STATUS_UA)
                base_content_type = str(plain_handoff_config.get("content_type") or "text/html")
                configured_service_type_h = str(plain_handoff_config.get("service_type") or "").strip()
                dest_port_h = str(plain_handoff_config.get("dest_port") or "34567")
                encrypt_h = str(plain_handoff_config.get("encrypt") or "1")
                configured_step_h = str(plain_handoff_config.get("step") or "").strip()
                protocol_mode_h = str(plain_handoff_config.get("protocol_mode") or "tcp")
                agent_ssl_verify_h = bool(plain_handoff_config.get("agent_ssl_verify"))
                service_type_h = configured_service_type_h or "RpsAV"
                step_h = configured_step_h or ("0" if service_type_h == "RpsCmd" else "8")
                bind_proxy_mode = str(plain_handoff_config.get("bind_proxy_mode") or "tcp_bind_proxy").strip().lower()
                probe_timeout_h = float(plain_handoff_config.get("probe_timeout") or min(timeout, 12.0))
                selector_timeout_h = max(1, int(float(plain_handoff_config.get("selector_timeout") or min(timeout, 15))))
                if bind_proxy_mode == "sdk_bind_proxy":
                    bind_proxy = LocalAgentSdkBindProxy(
                        access_host=server_ip,
                        access_port=int(server_port),
                        authcode=authcode,
                        serial=serial,
                        dest_port=dest_port_h,
                        service_type=service_type_h,
                        encrypt=encrypt_h,
                        step=step_h,
                        protocol_mode=protocol_mode_h,
                        vendor=str(plain_handoff_config.get("vendor") or ""),
                        developer_id=str(plain_handoff_config.get("developer_id") or ""),
                        app_key=str(plain_handoff_config.get("app_key") or ""),
                        timeout=probe_timeout_h,
                        user_agent=user_agent,
                        content_type=base_content_type,
                        ssl_verify=agent_ssl_verify_h,
                        agent_client_uuid=client_token,
                        prime_selector_early=bool(plain_handoff_config.get("prime_selector_early", False)),
                    )
                    bind_proxy.start()
                    if bool(plain_handoff_config.get("prime_selector_early", False)):
                        selector_wait_deadline = time.time() + min(3.0, max(0.5, float(selector_timeout_h)))
                        while time.time() < selector_wait_deadline:
                            bind_summary = bind_proxy.summary()
                            if bind_summary.get("selected_access") or bind_summary.get("access_attempts") or bind_summary.get("error"):
                                break
                            time.sleep(0.05)
                    bind_summary = bind_proxy.summary()
                    if bind_summary.get("status") == "error" or not int(bind_summary.get("local_port") or 0):
                        bind_proxy.close()
                        return {
                            "bind_proxy_mode": bind_proxy_mode,
                            "client_token": bind_proxy.agent_client_uuid,
                            "session_id": bind_proxy.agent_session_id,
                            "attempts": list(bind_summary.get("access_attempts") or []),
                            "selected": bind_summary.get("selected_access") or {},
                            "server": bind_summary.get("agent_server") or {},
                            "agent_bind": bind_summary,
                        }
                    return {
                        "bind_proxy_mode": bind_proxy_mode,
                        "client_token": bind_proxy.agent_client_uuid,
                        "session_id": bind_proxy.agent_session_id,
                        "attempts": list(bind_summary.get("access_attempts") or []),
                        "selected": bind_summary.get("selected_access") or {},
                        "server": bind_summary.get("agent_server") or {},
                        "bind_proxy": bind_proxy,
                        "agent_bind": bind_summary,
                    }

                handoff_client_token = client_token
                handoff_session_id = build_session_id()
                attempts_h, selected_h, agent_server_h = select_agent_server_via_query(
                    authcode=authcode,
                    serial=serial,
                    client_token=handoff_client_token,
                    dest_port=dest_port_h,
                    service_type=service_type_h,
                    session_id=handoff_session_id,
                    encrypt=encrypt_h,
                    step=step_h,
                    protocol_mode=protocol_mode_h,
                    vendor=str(plain_handoff_config.get("vendor") or ""),
                    access_urls=[f"https://{server_ip}:{server_port}/"],
                    content_types=_dedupe([base_content_type, "text/html", "application/json"]),
                    timeout=selector_timeout_h,
                    ssl_verify=agent_ssl_verify_h,
                    user_agent=user_agent,
                )
                if not agent_server_h.get("ip") or not int(agent_server_h.get("port") or 0):
                    return {
                        "bind_proxy_mode": bind_proxy_mode,
                        "client_token": handoff_client_token,
                        "session_id": handoff_session_id,
                        "attempts": attempts_h,
                        "selected": selected_h,
                        "server": agent_server_h,
                        "agent_bind": {
                            "status": "error",
                            "mode": bind_proxy_mode,
                            "error": "agent_access_no_response",
                        },
                    }
                bind_proxy = LocalAgentTcpBindProxy(
                    upstream_host=str(agent_server_h.get("ip") or ""),
                    upstream_port=int(agent_server_h.get("port") or 0),
                    authcode=authcode,
                    client_token=handoff_client_token,
                    serial=serial,
                    session=handoff_session_id,
                    random_str=str(agent_server_h.get("random_str") or ""),
                    timeout=probe_timeout_h,
                )
                bind_proxy.start()
                bind_summary = bind_proxy.summary()
                if bind_summary.get("status") == "error" or not int(bind_summary.get("local_port") or 0):
                    bind_proxy.close()
                    return {
                        "bind_proxy_mode": bind_proxy_mode,
                        "client_token": handoff_client_token,
                        "session_id": handoff_session_id,
                        "attempts": attempts_h,
                        "selected": selected_h,
                        "server": agent_server_h,
                        "agent_bind": bind_summary,
                    }
                return {
                    "bind_proxy_mode": bind_proxy_mode,
                    "client_token": handoff_client_token,
                    "session_id": handoff_session_id,
                    "attempts": attempts_h,
                    "selected": selected_h,
                    "server": agent_server_h,
                    "bind_proxy": bind_proxy,
                    "agent_bind": bind_summary,
                }

            def _refresh_prebound_plain_handoff_info() -> dict[str, Any]:
                if prebound_plain_bind_proxy is None:
                    return dict(prebound_plain_handoff_info)
                live_summary = prebound_plain_bind_proxy.summary()
                refreshed = dict(prebound_plain_handoff_info)
                refreshed["client_token"] = str(
                    getattr(prebound_plain_bind_proxy, "agent_client_uuid", "")
                    or refreshed.get("client_token")
                    or ""
                )
                refreshed["session_id"] = str(
                    getattr(prebound_plain_bind_proxy, "agent_session_id", "")
                    or getattr(prebound_plain_bind_proxy, "session", "")
                    or refreshed.get("session_id")
                    or ""
                )
                refreshed["agent_bind"] = live_summary
                if live_summary.get("selected_access"):
                    refreshed["selected"] = live_summary.get("selected_access") or {}
                if live_summary.get("agent_server"):
                    refreshed["server"] = live_summary.get("agent_server") or {}
                if live_summary.get("access_attempts"):
                    refreshed["attempts"] = list(live_summary.get("access_attempts") or [])
                if "bind_proxy" in prebound_plain_handoff_info:
                    refreshed["bind_proxy"] = prebound_plain_handoff_info["bind_proxy"]
                return refreshed

            def _maybe_prepare_plain_handoff_bind(reason: str) -> bool:
                nonlocal prebound_plain_handoff_info
                nonlocal prebound_plain_bind_proxy
                if not plain_handoff_config or not plain_handoff_prepare_early:
                    return False
                if prebound_plain_bind_proxy is not None or prebound_plain_handoff_info:
                    return False
                if reason != plain_handoff_prepare_stage:
                    return False
                _record_plain_handoff_event("prepare_bind_begin", reason=reason)
                prebound_plain_handoff_info = _prepare_plain_handoff_bind()
                bind_candidate = prebound_plain_handoff_info.get("bind_proxy")
                if isinstance(bind_candidate, (LocalAgentTcpBindProxy, LocalAgentSdkBindProxy)):
                    prebound_plain_bind_proxy = bind_candidate
                result["plain_handoff_prebind"] = {
                    "prepare_stage": plain_handoff_prepare_stage,
                    "bind_proxy_mode": prebound_plain_handoff_info.get("bind_proxy_mode"),
                    "selected": prebound_plain_handoff_info.get("selected") or {},
                    "server": prebound_plain_handoff_info.get("server") or {},
                    "agent_bind": prebound_plain_handoff_info.get("agent_bind") or {},
                    "client_token_masked": _mask_secret(str(prebound_plain_handoff_info.get("client_token") or ""), 8, 4),
                    "session_id_masked": _mask_secret(str(prebound_plain_handoff_info.get("session_id") or ""), 6, 4),
                    "attempts": list(prebound_plain_handoff_info.get("attempts") or []),
                }
                _record_plain_handoff_event(
                    "prepare_bind_ready",
                    reason=reason,
                    bind_proxy_mode=prebound_plain_handoff_info.get("bind_proxy_mode"),
                    selected_server=str(((prebound_plain_handoff_info.get("server") or {}).get("ip")) or ""),
                    selected_port=int(((prebound_plain_handoff_info.get("server") or {}).get("port")) or 0),
                )
                return True

            if plain_handoff_config and plain_handoff_prepare_early and plain_handoff_prepare_stage == "immediate":
                _maybe_prepare_plain_handoff_bind("immediate")

            def _forward_plain_handoff_payload(payload: bytes, vekey1: str) -> None:
                plain_handoff_live_data_seen.set()
                if plain_handoff_data_frame_callback is not None:
                    plain_handoff_data_frame_callback(payload, vekey1)

            def _maybe_start_plain_handoff(reason: str) -> bool:
                nonlocal plain_handoff_started
                nonlocal plain_handoff_pending
                nonlocal plain_handoff_thread
                nonlocal plain_handoff_join_timeout
                nonlocal prebound_plain_bind_proxy
                nonlocal prebound_plain_handoff_info
                if not plain_handoff_config or plain_handoff_started:
                    return False
                if not plain_handoff_pending:
                    return False
                if reason != plain_handoff_trigger:
                    return False
                _record_plain_handoff_event("start_plain_handoff_requested", reason=reason)
                if plain_handoff_recreate_bind_on_start:
                    if prebound_plain_bind_proxy is not None:
                        try:
                            prebound_plain_bind_proxy.close()
                        except Exception:
                            pass
                    prebound_plain_bind_proxy = None
                    prebound_plain_handoff_info = _prepare_plain_handoff_bind()
                    bind_candidate = prebound_plain_handoff_info.get("bind_proxy")
                    if isinstance(bind_candidate, (LocalAgentTcpBindProxy, LocalAgentSdkBindProxy)):
                        prebound_plain_bind_proxy = bind_candidate
                    result["plain_handoff_recreated_prebind"] = {
                        "selected": prebound_plain_handoff_info.get("selected") or {},
                        "server": prebound_plain_handoff_info.get("server") or {},
                        "agent_bind": prebound_plain_handoff_info.get("agent_bind") or {},
                        "client_token_masked": _mask_secret(
                            str(prebound_plain_handoff_info.get("client_token") or ""),
                            8,
                            4,
                        ),
                        "session_id_masked": _mask_secret(
                            str(prebound_plain_handoff_info.get("session_id") or ""),
                            6,
                            4,
                        ),
                        "attempts": list(prebound_plain_handoff_info.get("attempts") or []),
                    }
                def _worker() -> None:
                    try:
                        _record_plain_handoff_event("plain_handoff_worker_enter", reason=reason)
                        plain_handoff_async_result.update(_run_plain_handoff_rounds())
                        _record_plain_handoff_event(
                            "plain_handoff_worker_exit",
                            reason=reason,
                            runs=len(plain_handoff_async_result.get("plain_handoff_runs") or []),
                        )
                    except Exception as exc:  # noqa: BLE001
                        plain_handoff_async_result["probe"] = {
                            "status": "error",
                            "error": f"plain_handoff_thread_failed: {exc}",
                        }
                        _record_plain_handoff_event("plain_handoff_worker_error", reason=reason, error=str(exc))

                selector_timeout_v = float(plain_handoff_config.get("selector_timeout") or min(timeout, 15))
                probe_timeout_v = float(plain_handoff_config.get("probe_timeout") or min(timeout, 12.0))
                plain_handoff_join_timeout = max(1.0, selector_timeout_v + probe_timeout_v + 2.0)
                plain_handoff_thread = threading.Thread(
                    target=_worker,
                    name="icsee-plain-handoff",
                    daemon=True,
                )
                plain_handoff_thread.start()
                plain_handoff_started = True
                plain_handoff_pending = False
                result["plain_handoff_start_reason"] = reason
                result["plain_handoff_recreate_bind_on_start"] = plain_handoff_recreate_bind_on_start
                _record_plain_handoff_event("plain_handoff_thread_started", reason=reason)
                return True

            def _update_second_success_replay_state() -> None:
                nonlocal second_success_replay_state, second_success_replay_seen_at
                if controller_pending_seen and not controller_readying_seen:
                    second_success_replay_state = "pending_first_completion"
                if controller_readying_seen:
                    second_success_replay_state = "replay_window_open"
                if controller_readying_seen and late_064d_after_readying_seen:
                    second_success_replay_state = "replay_window_armed"
                if (
                    controller_readying_seen
                    and late_064d_after_readying_seen
                    and auto_retry_second582_done
                    and auto_retry_61a_done
                ):
                    second_success_replay_state = "second_success_replay_ready"
                    if second_success_replay_seen_at <= 0:
                        second_success_replay_seen_at = time.time()
                    _maybe_start_plain_handoff("after_second_success_replay")

            def _prepare_followup_send(followup: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
                payload_bytes = bytes(followup.get("payload_bytes") or b"")
                code_endian = str(followup.get("code_endian") or "be")
                followup_frame = _build_tcp_frame(
                    msg_type=int(followup.get("msg_type") or 0),
                    session_id=int(followup.get("session_id") or 0),
                    msg_id=int(followup.get("msg_id") or 0),
                    code=int(followup.get("code") or 0),
                    payload=payload_bytes,
                    unk=int(followup.get("unk") or 0),
                    cmd=int(followup.get("cmd") or 0),
                    code_endian=code_endian,
                )
                sent_summary = {
                    "msg_type": int(followup.get("msg_type") or 0),
                    "session_id": int(followup.get("session_id") or 0),
                    "msg_id": int(followup.get("msg_id") or 0),
                    "unk": int(followup.get("unk") or 0),
                    "cmd": int(followup.get("cmd") or 0),
                    "code": int(followup.get("code") or 0),
                    "code_endian": code_endian,
                    "send_phase": str(followup.get("send_phase") or ""),
                    "controller_profile": str(followup.get("controller_profile") or ""),
                    "burst_group": str(followup.get("burst_group") or ""),
                    "wait_for_response_cmd": int(followup.get("wait_for_response_cmd") or 0),
                    "wait_for_response_ret": followup.get("wait_for_response_ret"),
                    "payload_len": len(payload_bytes),
                    "payload_head_hex": payload_bytes[:32].hex(),
                    "plain_payload_text": str(followup.get("plain_payload_text") or ""),
                    "sent_at": time.time(),
                }
                return tx_cipher.apply(followup_frame), sent_summary

            def _followup_wait_satisfied(followup: dict[str, Any]) -> bool:
                wait_cmd = int(followup.get("wait_for_response_cmd") or 0)
                if wait_cmd <= 0:
                    return True
                if followup_wait_response_counts.get(wait_cmd, 0) <= 0:
                    return False
                expected = followup.get("wait_for_response_ret")
                if expected is None or expected == "":
                    return True
                actual = followup_wait_response_rets.get(wait_cmd)
                try:
                    return int(actual if actual is not None else -1) == int(expected)
                except Exception:
                    return False

            def _note_wait_response(frame: TcpFrame) -> None:
                if not followup_wait_response_cmds or int(frame.cmd or 0) not in followup_wait_response_cmds:
                    return
                summary = _summarize_tcp_frame(
                    frame,
                    dataenc_key=current_dataenc_key,
                    not_encrypt_cmds=current_not_encrypt_cmds,
                )
                payload_json = _frame_json_payload(summary)
                followup_wait_response_counts[int(frame.cmd)] += 1
                followup_wait_response_rets[int(frame.cmd)] = _intish(payload_json.get("Ret"), None)

            def _note_controller_keepalive_sent(followup: dict[str, Any]) -> None:
                nonlocal controller_keepalive_next_at, end_time
                if controller_keepalive_interval <= 0:
                    return
                if int(followup.get("cmd") or 0) != 0x03EE:
                    return
                now = time.time()
                controller_keepalive_next_at = now + controller_keepalive_interval
                end_time = max(end_time, controller_keepalive_next_at + controller_keepalive_grace)

            def _send_followup_dict(followup: dict[str, Any]) -> bool:
                nonlocal followup_send_error
                followup_cipher, sent_summary = _prepare_followup_send(followup)
                _emit_progress(f"TCP request {_tcp_progress_payload(sent_summary)}")
                try:
                    sock.sendall(followup_cipher)
                except OSError as exc:
                    sent_summary["send_error"] = str(exc)
                    _emit_progress(f"TCP request failed {_tcp_progress_payload(sent_summary)}")
                    followup_send_error = dict(sent_summary)
                    sent_followups.append(sent_summary)
                    return False
                _emit_progress(f"TCP request sent {_tcp_progress_payload(sent_summary)}")
                sent_followups.append(sent_summary)
                _note_controller_keepalive_sent(followup)
                return True

            def _next_dynamic_followup_msg_id() -> int:
                nonlocal dynamic_followup_msg_id
                candidates = [
                    int(dynamic_followup_msg_id or 0),
                    int(login_followup_msg_id or 0) + 2048,
                ]
                candidates.extend(int(item.get("msg_id") or 0) for item in followup_frames)
                candidates.extend(int(item.get("msg_id") or 0) for item in sent_followups)
                dynamic_followup_msg_id = max(candidates) + 8
                return dynamic_followup_msg_id

            def _request_delay_seconds(request: Any) -> float:
                if isinstance(request, dict):
                    return max(0.0, float(request.get("delay_before") or 0.0))
                return max(0.0, float(getattr(request, "delay_before", 0.0) or 0.0))

            def _dynamic_followups_ready() -> bool:
                if runtime_session_id_live <= 0 or login_success_seen_at <= 0:
                    return False
                if not (post_login_followups_queued or auto_controller_enqueued):
                    return False
                if followup_frames and not (
                    saw_data_frame
                    or controller_response_seen_at > 0
                    or audio_support_413_seen > 0
                    or plain_handoff_live_data_seen.is_set()
                ):
                    return False
                return True

            def _drain_dynamic_followup_queue() -> None:
                nonlocal dynamic_followups_enqueued, end_time, recv_error
                if dynamic_followup_queue is None or not _dynamic_followups_ready():
                    return
                now = time.time()
                drained = 0
                while drained < 16:
                    try:
                        request = dynamic_followup_queue.get_nowait()
                    except queue.Empty:
                        break
                    except Exception as exc:  # noqa: BLE001
                        recv_error = f"dynamic_followup_queue:{type(exc).__name__}: {exc}"
                        break
                    try:
                        delay = _request_delay_seconds(request)
                        followup = build_binary_ptz_followup(
                            request,
                            runtime_session_id=int(runtime_session_id_live),
                            msg_id=_next_dynamic_followup_msg_id(),
                            communicate_key=current_dataenc_key,
                        )
                    except Exception as exc:  # noqa: BLE001
                        _emit_progress(f"PTZ request build failed {type(exc).__name__}: {exc}")
                        continue
                    dynamic_followup_frames.append({"due_at": now + delay, "followup": followup})
                    dynamic_followups_enqueued += 1
                    drained += 1
                    end_time = max(end_time, now + delay + response_drain_seconds)
                    _emit_progress(
                        "PTZ request queued "
                        f"code={int(followup.get('ptz_code') or 0)} "
                        f"action={int(followup.get('ptz_action') or 0)} "
                        f"delay={delay:.2f}s"
                    )

            def _send_due_dynamic_followups() -> bool:
                nonlocal dynamic_followups_sent, end_time
                if not dynamic_followup_frames:
                    return True
                dynamic_followup_frames.sort(key=lambda item: float(item.get("due_at") or 0.0))
                now = time.time()
                while dynamic_followup_frames and float(dynamic_followup_frames[0].get("due_at") or 0.0) <= now:
                    item = dynamic_followup_frames.pop(0)
                    followup = item.get("followup")
                    if not isinstance(followup, dict):
                        continue
                    if not _send_followup_dict(followup):
                        end_time = time.time()
                        return False
                    dynamic_followups_sent += 1
                    end_time = max(end_time, time.time() + response_drain_seconds)
                return True

            def _send_followup_batch(group: list[dict[str, Any]]) -> bool:
                nonlocal followup_send_error
                if not group:
                    return True
                cipher_frames: list[bytes] = []
                group_summaries: list[dict[str, Any]] = []
                for item in group:
                    cipher_frame, sent_summary = _prepare_followup_send(item)
                    sent_summary["send_mode"] = "burst_batch"
                    cipher_frames.append(cipher_frame)
                    group_summaries.append(sent_summary)
                batch_label = ", ".join(
                    f"0x{int(item.get('cmd') or 0):04x}/msg={int(item.get('msg_id') or 0)}"
                    for item in group_summaries
                )
                _emit_progress(f"TCP batch request count={len(group_summaries)} {batch_label}")
                try:
                    sock.sendall(b"".join(cipher_frames))
                except OSError as exc:
                    for sent_summary in group_summaries:
                        sent_summary["send_error"] = str(exc)
                        sent_followups.append(sent_summary)
                    _emit_progress(f"TCP batch request failed count={len(group_summaries)}")
                    followup_send_error = dict(group_summaries[0])
                    return False
                _emit_progress(f"TCP batch request sent count={len(group_summaries)}")
                sent_followups.extend(group_summaries)
                return True

            def _schedule_followup_window() -> None:
                nonlocal followup_schedule_started_at, followup_next_due_at
                if not followup_frames:
                    followup_schedule_started_at = 0.0
                    followup_next_due_at = 0.0
                    return
                if followup_schedule_started_at <= 0:
                    followup_schedule_started_at = time.time()
                    first_frame_delay = max(0.0, float((followup_frames[0].get("delay_before") or 0.0)))
                    followup_next_due_at = (
                        followup_schedule_started_at
                        + max(0.0, float(followup_delay))
                        + first_frame_delay
                    )
                    return
                if followup_next_due_at <= 0:
                    followup_next_due_at = time.time()

            def _send_next_followup_window() -> bool:
                nonlocal followup_frames, end_time
                if not followup_frames:
                    return True
                followup = followup_frames[0]
                if not _followup_wait_satisfied(followup):
                    return True
                frame_delay = float(followup.get("delay_before") or 0.0)
                if frame_delay > 0:
                    time.sleep(frame_delay)
                burst_group = str(followup.get("burst_group") or "").strip()
                if burst_group:
                    grouped_followups = [followup]
                    next_index = 1
                    while next_index < len(followup_frames):
                        candidate = followup_frames[next_index]
                        if str(candidate.get("burst_group") or "").strip() != burst_group:
                            break
                        grouped_followups.append(candidate)
                        next_index += 1
                    send_ok = _send_followup_batch(grouped_followups)
                    del followup_frames[:next_index]
                else:
                    send_ok = _send_followup_dict(followup)
                    del followup_frames[:1]
                if send_ok and (
                    login_followup_builder is None
                    or login_success_seen_at > 0
                    or post_login_followups_queued
                ):
                    _maybe_start_plain_handoff("after_first_followup")
                    end_time = max(end_time, time.time() + response_drain_seconds)
                return send_ok

            def _run_plain_handoff_rounds() -> dict[str, Any]:
                handoff_result_bundle: dict[str, Any] = {
                    "plain_handoff_runs": [],
                    "plain_handoff_agent_http": {},
                    "plain_handoff_agent_server": {},
                    "plain_handoff_probe": {},
                }
                if not plain_handoff_config:
                    return handoff_result_bundle
                plain_session_int = int(runtime_session_id_live) if int(runtime_session_id_live or 0) > 0 else 0x78
                replay_count_raw = plain_handoff_config.get("claim_replay_count")
                replay_count_h = max(0, int(1 if replay_count_raw is None else replay_count_raw))
                replay_delay_h = float(plain_handoff_config.get("claim_replay_delay") or 0.35)
                replay_delay_step_h = float(plain_handoff_config.get("claim_replay_delay_step") or 0.45)
                replay_msgid_step_h = max(1, int(plain_handoff_config.get("claim_replay_msgid_step") or 1))
                handoff_stream_type_h = str(plain_handoff_config.get("stream_type") or "Extra1")
                handoff_combine_mode_h = "CONNECT_ALL" if handoff_stream_type_h.strip().lower() == "main" else "NONE"
                plain_initial_payload_text = str(plain_handoff_config.get("initial_payload_text") or "")
                plain_initial_code_raw = plain_handoff_config.get("initial_code")
                plain_initial_code = int(plain_initial_code_raw) if plain_initial_code_raw is not None else None
                plain_replay_followups = build_plain_claim_replay_followups(
                    session_int=plain_session_int,
                    channel=channel,
                    stream_type=handoff_stream_type_h,
                    trans_mode="TCP",
                    combine_mode=handoff_combine_mode_h,
                    msg_id=0x18,
                    code=0x00008505,
                    code_endian="be",
                    replay_count=replay_count_h,
                    first_delay=replay_delay_h,
                    delay_step=replay_delay_step_h,
                    msg_id_step=replay_msgid_step_h,
                )
                if prebound_plain_bind_proxy is not None and prebound_plain_handoff_info:
                    current_prebound = _refresh_prebound_plain_handoff_info()
                    _record_plain_handoff_event(
                        "run_prebound_probe_begin",
                        bind_proxy_mode=current_prebound.get("bind_proxy_mode"),
                        selected_server=str(((current_prebound.get("server") or {}).get("ip")) or ""),
                        selected_port=int(((current_prebound.get("server") or {}).get("port")) or 0),
                    )
                    handoff_result = run_prebound_local_agent_live_probe(
                        bind_proxy=prebound_plain_bind_proxy,
                        authcode=authcode,
                        client_token=str(current_prebound.get("client_token") or ""),
                        serial=serial,
                        session=str(current_prebound.get("session_id") or ""),
                        session_int=plain_session_int,
                        channel=channel,
                        stream_type=handoff_stream_type_h,
                        trans_mode="TCP",
                        combine_mode=handoff_combine_mode_h,
                        msg_id=0x18,
                        code=0x00008505,
                        code_endian="be",
                        timeout=float(plain_handoff_config.get("probe_timeout") or min(timeout, 12.0)),
                        capture_seconds=capture_seconds,
                        max_frames=max_frames,
                        media_random_str=current_media_random_str,
                        vekey1=current_vekey1,
                        followup_frames=plain_replay_followups,
                        initial_payload_text=plain_initial_payload_text,
                        initial_code=plain_initial_code,
                        on_data_frame_payload=_forward_plain_handoff_payload,
                        stop_event=stop_event,
                        extend_on_activity=plain_handoff_extend_on_activity,
                    )
                    _record_plain_handoff_event(
                        "run_prebound_probe_end",
                        bind_proxy_mode=current_prebound.get("bind_proxy_mode"),
                        probe_status=str(handoff_result.get("status") or ""),
                        handshake_ok=bool(((handoff_result.get("handshake") or {}).get("ok"))),
                    )
                    handoff_result["controller_summary"] = analyze_live_controller_flow(handoff_result)
                    handoff_result["local_bootstrap_summary"] = _ensure_local_bootstrap_summary(
                        handoff_result,
                        controller_status=str((handoff_result.get("controller_summary") or {}).get("status") or ""),
                        media_random_str=str(handoff_result.get("media_random_str") or current_media_random_str or ""),
                        vekey1=str(handoff_result.get("vekey1") or current_vekey1 or ""),
                    )
                    handoff_result_bundle["plain_handoff_runs"].append(
                        {
                            "round": 0,
                            "prepared_early": True,
                            "bind_proxy_mode": current_prebound.get("bind_proxy_mode"),
                            "client_token_masked": _mask_secret(str(current_prebound.get("client_token") or ""), 8, 4),
                            "session_id_masked": _mask_secret(str(current_prebound.get("session_id") or ""), 6, 4),
                            "runtime_plain_session": f"0x{plain_session_int:010x}",
                            "agent_http": {
                                "selected": current_prebound.get("selected") or {},
                                "attempts": list(current_prebound.get("attempts") or []),
                            },
                            "agent_server": current_prebound.get("server") or {},
                            "agent_bind": handoff_result.get("agent_bind") or {},
                            "probe": handoff_result,
                        }
                    )
                    handoff_result_bundle["plain_handoff_agent_http"] = {
                        "selected": current_prebound.get("selected") or {},
                        "attempts": list(current_prebound.get("attempts") or []),
                        "client_token_masked": _mask_secret(str(current_prebound.get("client_token") or ""), 8, 4),
                        "session_id_masked": _mask_secret(str(current_prebound.get("session_id") or ""), 6, 4),
                        "prepared_early": True,
                        "bind_proxy_mode": current_prebound.get("bind_proxy_mode"),
                    }
                    handoff_result_bundle["plain_handoff_agent_server"] = current_prebound.get("server") or {}
                    handoff_result_bundle["plain_handoff_probe"] = handoff_result
                    return handoff_result_bundle
                server_ip = str(plain_handoff_config.get("status_server_ip") or "").strip()
                server_port = str(plain_handoff_config.get("status_server_port") or "").strip()
                if not server_ip or not server_port:
                    return handoff_result_bundle
                handoff_rounds = max(1, int(plain_handoff_config.get("rounds") or 3))
                handoff_probe_timeout = float(plain_handoff_config.get("probe_timeout") or min(timeout, 12.0))
                selector_timeout = int(plain_handoff_config.get("selector_timeout") or min(timeout, 15))
                user_agent = str(plain_handoff_config.get("user_agent") or DEFAULT_STATUS_UA)
                base_content_type = str(plain_handoff_config.get("content_type") or "text/html")
                configured_service_type_h = str(plain_handoff_config.get("service_type") or "").strip()
                dest_port_h = str(plain_handoff_config.get("dest_port") or "34567")
                encrypt_h = str(plain_handoff_config.get("encrypt") or "1")
                configured_step_h = str(plain_handoff_config.get("step") or "").strip()
                protocol_mode_h = str(plain_handoff_config.get("protocol_mode") or "tcp")
                agent_ssl_verify_h = bool(plain_handoff_config.get("agent_ssl_verify"))
                reuse_outer_client_token = bool(plain_handoff_config.get("reuse_outer_client_token", True))
                reuse_outer_session_id = bool(plain_handoff_config.get("reuse_outer_session_id", True))
                service_types_h = [configured_service_type_h] if configured_service_type_h else ["RpsAV"]
                agent_urls_h = _dedupe(
                    [
                        f"https://{server_ip}:{server_port}/",
                    ]
                )
                agent_content_types_h = _dedupe([base_content_type, "text/html", "application/json"])
                best_handoff_attempt: dict[str, Any] = {}
                best_handoff_server: dict[str, Any] = {}
                best_handoff_probe: dict[str, Any] = {}
                best_handoff_score = -1
                for handoff_round in range(1, handoff_rounds + 1):
                    handoff_client_token = client_token if reuse_outer_client_token else build_client_token()
                    handoff_session_id = session if reuse_outer_session_id else build_session_id()
                    handoff_attempts: list[dict[str, Any]] = []
                    handoff_pick: dict[str, Any] = {}
                    for service_type_h in service_types_h:
                        step_h = configured_step_h or ("0" if service_type_h == "RpsCmd" else "8")
                        handoff_payloads = build_agent_payload_variants(
                            authcode=authcode,
                            serial_number=serial,
                            client_token=handoff_client_token,
                            dest_port=dest_port_h,
                            service_type=service_type_h,
                            session_id=handoff_session_id,
                            encrypt=encrypt_h,
                            step=step_h,
                            protocol_mode=protocol_mode_h,
                            vendor=str(plain_handoff_config.get("vendor") or ""),
                        )
                        for handoff_payload in handoff_payloads:
                            payload_body = handoff_payload.get("AgentProtocol", {}).get("Body", {})
                            for agent_url in agent_urls_h:
                                for content_type in agent_content_types_h:
                                    handoff_res = agent_protocol_query(
                                        url=agent_url,
                                        payload=handoff_payload,
                                        timeout=selector_timeout,
                                        ssl_verify=agent_ssl_verify_h if agent_url.startswith("https://") else False,
                                        user_agent=user_agent,
                                        content_type=content_type,
                                    )
                                    handoff_parsed = parse_agent_protocol_response(handoff_res.json_data)
                                    attempt = {
                                        "ok": handoff_res.ok,
                                        "status": handoff_res.status,
                                        "url": handoff_res.url,
                                        "content_type": content_type,
                                        "service_type": payload_body.get("ServiceType"),
                                        "step": payload_body.get("Step"),
                                        "parsed": handoff_parsed,
                                        "response_head": (handoff_res.text or "")[:400],
                                        "error": handoff_res.error,
                                    }
                                    handoff_attempts.append(attempt)
                                    if handoff_parsed.get("agent_server_ip") and handoff_parsed.get("agent_server_port"):
                                        handoff_pick = attempt
                                        break
                                if handoff_pick:
                                    break
                            if handoff_pick:
                                break
                        if handoff_pick:
                            break

                    handoff_round_result: dict[str, Any] = {
                        "round": handoff_round,
                        "client_token_masked": _mask_secret(handoff_client_token, 8, 4),
                        "client_token_source": "outer" if reuse_outer_client_token else "generated",
                        "session_id_masked": _mask_secret(handoff_session_id, 6, 4),
                        "runtime_plain_session": f"0x{plain_session_int:010x}",
                        "service_type_candidates": service_types_h,
                        "agent_http": {
                            "selected": handoff_pick,
                            "attempts": handoff_attempts,
                        },
                    }
                    handoff_parsed = handoff_pick.get("parsed") if isinstance(handoff_pick.get("parsed"), dict) else {}
                    if handoff_parsed.get("agent_server_ip") and handoff_parsed.get("agent_server_port"):
                        handoff_server = {
                            "ip": handoff_parsed.get("agent_server_ip"),
                            "port": int(handoff_parsed.get("agent_server_port") or 0),
                            "random_str": handoff_parsed.get("random_str"),
                            "protocol_mode": handoff_parsed.get("protocol_mode"),
                        }
                        handoff_round_result["agent_server"] = handoff_server
                        handoff_result = run_local_agent_live_probe(
                            upstream_host=str(handoff_parsed.get("agent_server_ip")),
                            upstream_port=int(handoff_parsed.get("agent_server_port") or 0),
                            authcode=authcode,
                            client_token=handoff_client_token,
                            serial=serial,
                            session=handoff_session_id,
                            session_int=plain_session_int,
                            channel=channel,
                            stream_type=handoff_stream_type_h,
                            trans_mode="TCP",
                            combine_mode=handoff_combine_mode_h,
                            msg_id=0x18,
                            code=0x00008505,
                            code_endian="be",
                            timeout=handoff_probe_timeout,
                            capture_seconds=capture_seconds,
                            max_frames=max_frames,
                            random_str=str(handoff_parsed.get("random_str") or ""),
                            media_random_str=current_media_random_str,
                            vekey1=current_vekey1,
                            followup_frames=plain_replay_followups,
                            initial_payload_text=plain_initial_payload_text,
                            initial_code=plain_initial_code,
                            on_data_frame_payload=_forward_plain_handoff_payload,
                            stop_event=stop_event,
                            extend_on_activity=plain_handoff_extend_on_activity,
                        )
                        handoff_round_result["agent_bind"] = handoff_result.get("agent_bind") or {}
                        handoff_result["controller_summary"] = analyze_live_controller_flow(handoff_result)
                        handoff_result["local_bootstrap_summary"] = _ensure_local_bootstrap_summary(
                            handoff_result,
                            controller_status=str((handoff_result.get("controller_summary") or {}).get("status") or ""),
                            media_random_str=str(handoff_result.get("media_random_str") or current_media_random_str or ""),
                            vekey1=str(handoff_result.get("vekey1") or current_vekey1 or ""),
                        )
                        handoff_round_result["probe"] = handoff_result
                        data_count = int((((handoff_result.get("frames") or {}).get("data")) or 0))
                        handshake_ok = bool(((handoff_result.get("handshake") or {}).get("ok")))
                        control_count = int((((handoff_result.get("frames") or {}).get("control")) or 0))
                        score = (1000 if data_count > 0 else 0) + (100 if control_count > 0 else 0) + (10 if handshake_ok else 0)
                        if score > best_handoff_score:
                            best_handoff_score = score
                            best_handoff_attempt = {
                                "selected": handoff_pick,
                                "attempts": handoff_attempts,
                                "client_token_masked": _mask_secret(handoff_client_token, 8, 4),
                                "session_id_masked": _mask_secret(handoff_session_id, 6, 4),
                            }
                            best_handoff_server = dict(handoff_server)
                            best_handoff_probe = handoff_result
                        if data_count > 0 or str(handoff_result.get("status") or "") == "ok":
                            handoff_result_bundle["plain_handoff_runs"].append(handoff_round_result)
                            break
                    handoff_result_bundle["plain_handoff_runs"].append(handoff_round_result)
                handoff_result_bundle["plain_handoff_agent_http"] = best_handoff_attempt
                handoff_result_bundle["plain_handoff_agent_server"] = best_handoff_server
                handoff_result_bundle["plain_handoff_probe"] = best_handoff_probe
                return handoff_result_bundle

            end_time = time.time() + max(0.5, capture_seconds)
            while time.time() < end_time and len(frames) < max_frames and not (stop_event is not None and stop_event.is_set()):
                _drain_dynamic_followup_queue()
                if not _send_due_dynamic_followups():
                    break
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    chunk = b""
                except (ConnectionAbortedError, ConnectionResetError, OSError) as exc:
                    recv_error = f"{type(exc).__name__}: {exc}"
                    break
                if not chunk:
                    pass
                else:
                    received.extend(chunk)
                    decoded_chunk = rx_cipher.apply(chunk)
                    decoded_stream.extend(decoded_chunk)
                    buffer += decoded_chunk
                    parsed_frames, buffer = _parse_tcp_frames(buffer)
                    if parsed_frames:
                        frames.extend(parsed_frames)
                        for parsed_frame in parsed_frames:
                            if parsed_frame.msg_type == 1 or parsed_frame.cmd == 0x058E:
                                if not saw_data_frame:
                                    _emit_progress(
                                        f"TCP media response first packet cmd=0x{int(parsed_frame.cmd):04x} "
                                        f"bytes={len(parsed_frame.payload)}"
                                    )
                                saw_data_frame = True
                                if plain_handoff_data_frame_callback is not None:
                                    try:
                                        plain_handoff_data_frame_callback(
                                            bytes(parsed_frame.payload),
                                            current_vekey1,
                                        )
                                    except Exception as exc:  # noqa: BLE001
                                        recv_error = f"data_frame_callback:{type(exc).__name__}: {exc}"
                                        end_time = time.time()
                                        if stop_event is not None:
                                            stop_event.set()
                                continue
                            progress_summary = _summarize_tcp_frame(
                                parsed_frame,
                                dataenc_key=current_dataenc_key,
                                not_encrypt_cmds=current_not_encrypt_cmds,
                            )
                            _emit_progress(f"TCP response {_tcp_progress_payload(progress_summary)}")
                            _note_wait_response(parsed_frame)
                            if parsed_frame.cmd in stop_after_response_cmds:
                                end_time = min(end_time, time.time() + 0.2)
                            if parsed_frame.cmd == 0x03E9:
                                login_payload = parsed_frame.payload.decode("utf-8", errors="ignore").strip("\x00\r\n ")
                                try:
                                    login_json = json.loads(login_payload) if login_payload.startswith("{") else {}
                                except Exception:
                                    login_json = {}
                                if int(login_json.get("Ret") or 0) == 100:
                                    login_success_seen_at = time.time()
                                    runtime_session_id_live = int(parsed_frame.session_id or 0)
                                    raw_session = str(login_json.get("SessionID") or "").strip()
                                    if raw_session:
                                        try:
                                            runtime_session_id_live = int(raw_session, 0)
                                        except Exception:
                                            pass
                                    _record_plain_handoff_event("login_success", runtime_session=runtime_session_id_live)
                                    _maybe_prepare_plain_handoff_bind("after_login")
                            elif parsed_frame.cmd == 0x0583:
                                controller_response_seen_at = time.time()
                                controller_summary = _summarize_tcp_frame(
                                    parsed_frame,
                                    dataenc_key=current_dataenc_key,
                                    not_encrypt_cmds=current_not_encrypt_cmds,
                                )
                                controller_json = _frame_json_payload(controller_summary)
                                controller_ret_latest = _intish(controller_json.get("Ret"), None)
                                if controller_ret_latest == 103:
                                    controller_pending_seen = True
                                if controller_ret_latest == 101:
                                    controller_readying_seen = True
                                _update_second_success_replay_state()
                                _maybe_start_plain_handoff("after_583")
                                if controller_ret_latest == 101:
                                    _maybe_start_plain_handoff("after_readying_101")
                            elif parsed_frame.cmd == 0x061B:
                                _maybe_start_plain_handoff("after_61b")
                            elif parsed_frame.cmd == 0x0591:
                                playback_claim_summary = _summarize_tcp_frame(
                                    parsed_frame,
                                    dataenc_key=current_dataenc_key,
                                    not_encrypt_cmds=current_not_encrypt_cmds,
                                )
                                playback_claim_json = _frame_json_payload(playback_claim_summary)
                                playback_claim_ret = _intish(playback_claim_json.get("Ret"), None)
                                _record_plain_handoff_event(
                                    "playback_claim_response",
                                    ret=playback_claim_ret,
                                )
                                if playback_claim_ret == 100 and plain_handoff_config and not plain_handoff_started:
                                    plain_handoff_pending = True
                                    _maybe_start_plain_handoff("after_playback_claim_591")
                            elif parsed_frame.cmd == 0x0551:
                                if controller_pending_seen:
                                    post582_0551_seen += 1
                                    if post582_0551_seen >= 2 and post582_064b_seen >= 1 and post582_03fd_seen:
                                        _maybe_start_plain_handoff("after_post582_cluster")
                            elif parsed_frame.cmd == 0x064B:
                                if controller_pending_seen:
                                    post582_064b_seen += 1
                                    if post582_0551_seen >= 2 and post582_064b_seen >= 1 and post582_03fd_seen:
                                        _maybe_start_plain_handoff("after_post582_cluster")
                            elif parsed_frame.cmd == 0x03FD:
                                if controller_pending_seen:
                                    post582_03fd_seen = True
                                    if post582_0551_seen >= 2 and post582_064b_seen >= 1:
                                        _maybe_start_plain_handoff("after_post582_cluster")
                            elif parsed_frame.cmd == 0x0413:
                                audio_support_413_seen += 1
                                _record_plain_handoff_event(
                                    "0413_seen",
                                    count=audio_support_413_seen,
                                    msg_id=int(parsed_frame.msg_id),
                                )
                                if audio_support_413_seen >= 2:
                                    _maybe_start_plain_handoff("after_second_413")
                                if response_gated_followups and followup_frames and audio_support_413_seen <= 2:
                                    if not _send_next_followup_window():
                                        end_time = time.time()
                                    if audio_support_413_seen >= 2:
                                        response_gated_followups_release_pending = True
                                if audio_support_413_seen >= 3:
                                    if third_413_seen_at <= 0:
                                        third_413_seen_at = time.time()
                                    _maybe_start_plain_handoff("after_third_413")
                                if audio_support_413_seen >= 6:
                                    _maybe_start_plain_handoff("after_sixth_413")
                            elif parsed_frame.cmd == 0x064D and controller_ret_latest == 101:
                                late_064d_after_readying_seen = True
                                _update_second_success_replay_state()
                                _maybe_start_plain_handoff("after_late_064d")
                if login_followup_builder and not followup_frames and not login_followup_done:
                    claim_response_live = next(
                        (item for item in frames if item.msg_type == 0 and item.cmd == (cmd + 1)),
                        None,
                    )
                    if claim_response_live is not None:
                        claim_response_summary_live = _summarize_tcp_frame(claim_response_live)
                        claim_json = claim_response_summary_live.get("aes_decrypted_json")
                        if isinstance(claim_json, dict) and claim_json:
                            builder_kwargs = dict(login_followup_builder)
                            msg_id_value = (
                                int(builder_kwargs["msg_id"])
                                if "msg_id" in builder_kwargs and builder_kwargs.get("msg_id") is not None
                                else int(claim_response_live.msg_id) + 8
                            )
                            built_login = build_6611_login_candidate(
                                claim_source=claim_json,
                                device_id=serial,
                                username=str(builder_kwargs.pop("username", "") or ""),
                                password=str(builder_kwargs.pop("password", "") or ""),
                                admin_token=str(builder_kwargs.pop("admin_token", "") or ""),
                                login_type=str(builder_kwargs.pop("login_type", "DVRIP-Web") or "DVRIP-Web"),
                                token_username=str(builder_kwargs.pop("token_username", "") or ""),
                                random_a=str(builder_kwargs.pop("random_a", "") or ""),
                                random_b=str(builder_kwargs.pop("random_b", "") or ""),
                                user_agent=str(builder_kwargs.pop("user_agent", "") or ""),
                                communicate_key=str(builder_kwargs.pop("communicate_key", "") or ""),
                                transport_key=str(builder_kwargs.pop("transport_key", "") or ""),
                                media_random_str=str(builder_kwargs.pop("media_random_str", "") or ""),
                                mode=str(builder_kwargs.pop("mode", "auto") or "auto"),
                                msg_type=int(builder_kwargs.pop("msg_type", 0) or 0),
                                session_id=int(builder_kwargs.pop("session_id", 0) or 0),
                                msg_id=msg_id_value,
                                unk=int(builder_kwargs.pop("unk", 0x63) or 0x63),
                                cmd=int(builder_kwargs.pop("cmd", 0x03E8) or 0x03E8),
                            )
                            built_login_summary = {
                                "status": built_login.get("status"),
                                "mode": built_login.get("mode"),
                                "transport_mode": ((built_login.get("transport") or {}).get("mode")),
                                "payload_len": ((built_login.get("transport") or {}).get("payload_len")),
                                "payload_b64_len": ((built_login.get("transport") or {}).get("payload_b64_len")),
                                "frame_len": ((built_login.get("frame") or {}).get("frame_len")),
                                "frame_msg_id": ((built_login.get("frame") or {}).get("msg_id")),
                                "frame_session_id": ((built_login.get("frame") or {}).get("session_id")),
                                "claim_public_key_head": str(claim_json.get("PublicKey") or "")[:32],
                                "communicate_key_len": len(str(built_login.get("communicate_key_raw") or "")),
                                "communicate_key_raw": str(built_login.get("communicate_key_raw") or ""),
                                "media_random_str_len": len(str(built_login.get("media_random_str_raw") or "")),
                                "media_random_str_raw": str(built_login.get("media_random_str_raw") or ""),
                                "vekey1_len": len(str(built_login.get("vekey1_raw") or "")),
                                "vekey1_raw": str(built_login.get("vekey1_raw") or ""),
                                "not_encrypt_count": len(claim_json.get("NotEncryptMsgID") or []),
                            }
                            current_dataenc_key = str(built_login.get("communicate_key_raw") or "")
                            current_media_random_str = _normalize_media_random_str(
                                str(built_login.get("media_random_str_raw") or "")
                            )
                            current_vekey1 = _normalize_media_random_str(
                                str(built_login.get("vekey1_raw") or "")
                            )
                            if isinstance(claim_json.get("NotEncryptMsgID"), list):
                                current_not_encrypt_cmds = {
                                    int(item)
                                    for item in claim_json.get("NotEncryptMsgID")
                                    if isinstance(item, int) or (isinstance(item, str) and item.isdigit())
                                }
                            login_followup_cmd = int(((built_login.get("frame") or {}).get("cmd")) or 0x03E8)
                            login_followup_msg_id = int(((built_login.get("frame") or {}).get("msg_id")) or 0)
                            login_followup_done = True
                            if built_login.get("status") == "ok":
                                transport = built_login.get("transport") if isinstance(built_login.get("transport"), dict) else {}
                                frame_meta = built_login.get("frame") if isinstance(built_login.get("frame"), dict) else {}
                                payload_text = str(transport.get("payload_text") or "")
                                followup_frames.append(
                                    {
                                        "msg_type": int(frame_meta.get("msg_type") or 0),
                                        "session_id": int(frame_meta.get("session_id") or 0),
                                        "msg_id": int(frame_meta.get("msg_id") or 0),
                                        "unk": int(frame_meta.get("unk") or 0),
                                        "cmd": int(frame_meta.get("cmd") or 0),
                                        "code": 0,
                                        "code_endian": "be",
                                        "payload_bytes": payload_text.encode("utf-8") + b"\x00",
                                    }
                                )
                                if pre_login_followup_templates:
                                    template_msg_base = min(int(item.get("msg_id") or 0) for item in pre_login_followup_templates)
                                    runtime_msg_base = int(frame_meta.get("msg_id") or 0) + 16
                                    for template in pre_login_followup_templates:
                                        rebased = dict(template)
                                        template_msg_id = int(template.get("msg_id") or 0)
                                        rebased["msg_id"] = runtime_msg_base + (template_msg_id - template_msg_base)
                                        plain_payload_text = rebased.get("plain_payload_text")
                                        if isinstance(plain_payload_text, str) and plain_payload_text:
                                            runtime_plain = plain_payload_text
                                            if current_vekey1:
                                                runtime_plain = runtime_plain.replace("{{VEKEY1}}", current_vekey1)
                                            if current_dataenc_key and rebased.get("dataenc") is not False:
                                                rebuilt = build_6611_dataenc_followup(
                                                    cmd=int(rebased.get("cmd") or 0),
                                                    plain_payload_text=runtime_plain,
                                                    communicate_key=current_dataenc_key,
                                                    msg_type=int(rebased.get("msg_type") or 0),
                                                    session_id=int(rebased.get("session_id") or 0),
                                                    msg_id=int(rebased.get("msg_id") or 0),
                                                    unk=int(rebased.get("unk") or 0),
                                                )
                                                rebased["payload_bytes"] = bytes(rebuilt.get("payload_bytes") or b"")
                                            else:
                                                rebased["payload_bytes"] = runtime_plain.encode("utf-8") + b"\x00"
                                            rebased["plain_payload_text"] = runtime_plain
                                        followup_frames.append(rebased)
                if login_followup_builder and not post_login_followups_queued:
                    login_response_live = next(
                        (item for item in frames if item.msg_type == 0 and item.cmd == (login_followup_cmd + 1)),
                        None,
                    )
                    if login_response_live is not None:
                        login_payload = login_response_live.payload.decode("utf-8", errors="ignore").strip("\x00\r\n ")
                        login_json: dict[str, Any] = {}
                        if login_payload.startswith("{"):
                            try:
                                login_json = json.loads(login_payload)
                            except Exception:
                                login_json = {}
                        if int(login_json.get("Ret") or 0) == 100:
                            runtime_session_id = int(login_response_live.session_id or 0)
                            raw_session = str(login_json.get("SessionID") or "").strip()
                            if raw_session:
                                try:
                                    runtime_session_id = int(raw_session, 0)
                                except Exception:
                                    pass
                            if plain_handoff_config and not plain_handoff_started:
                                plain_handoff_pending = True
                                _maybe_start_plain_handoff("after_login")
                            runtime_msg_base = int(login_followup_msg_id or login_response_live.msg_id) + 16
                            preserve_template_msg_ids = bool(
                                controller_profile == "app_reference_first_6611"
                            )
                            if post_login_followup_templates:
                                template_msg_base = min(int(item.get("msg_id") or 0) for item in post_login_followup_templates)
                                for template in post_login_followup_templates:
                                    rebased = dict(template)
                                    template_msg_id = int(template.get("msg_id") or 0)
                                    rebased["session_id"] = runtime_session_id
                                    if preserve_template_msg_ids and template_msg_id > 0:
                                        rebased["msg_id"] = template_msg_id
                                    else:
                                        rebased["msg_id"] = runtime_msg_base + (template_msg_id - template_msg_base)
                                    plain_payload_text = rebased.get("plain_payload_text")
                                    if isinstance(plain_payload_text, str) and plain_payload_text:
                                        runtime_plain = plain_payload_text
                                        if raw_session:
                                            runtime_plain = runtime_plain.replace("{{SESSION_ID}}", raw_session)
                                        if current_vekey1:
                                            runtime_plain = runtime_plain.replace("{{VEKEY1}}", current_vekey1)
                                        if current_dataenc_key and rebased.get("dataenc") is not False:
                                            rebuilt = build_6611_dataenc_followup(
                                                cmd=int(rebased.get("cmd") or 0),
                                                plain_payload_text=runtime_plain,
                                                communicate_key=current_dataenc_key,
                                                msg_type=int(rebased.get("msg_type") or 0),
                                                session_id=int(rebased.get("session_id") or 0),
                                                msg_id=int(rebased.get("msg_id") or 0),
                                                unk=int(rebased.get("unk") or 0),
                                            )
                                            rebased["payload_bytes"] = bytes(rebuilt.get("payload_bytes") or b"")
                                        else:
                                            rebased["payload_bytes"] = runtime_plain.encode("utf-8") + b"\x00"
                                        rebased["plain_payload_text"] = runtime_plain
                                    followup_frames.append(rebased)
                                post_login_followups_queued = True
                                if runtime_session_id:
                                    runtime_session_id_live = runtime_session_id
                            elif controller_auto and current_dataenc_key and not auto_controller_enqueued:
                                auto_followups = build_controller_auto_followups(
                                    profile=controller_profile,
                                    runtime_session_id=runtime_session_id,
                                    runtime_msg_id=runtime_msg_base,
                                    communicate_key=current_dataenc_key,
                                    media_random_str=current_media_random_str,
                                    vekey1=current_vekey1,
                                    device_id=serial,
                                    channel=channel,
                                    stream_type=stream_type,
                                    trans_mode=trans_mode,
                                    combine_mode=combine_mode,
                                )
                                if auto_followups:
                                    followup_frames.extend(auto_followups)
                                    auto_controller_enqueued = True
                                    if response_gated_followups and not response_gated_followups_started:
                                        if not _send_next_followup_window():
                                            end_time = time.time()
                                        response_gated_followups_started = True
                                    post_login_followups_queued = True
                                    if runtime_session_id:
                                        runtime_session_id_live = runtime_session_id
                                    login_success_seen_at = time.time()
                if (
                    plain_handoff_pending
                    and not plain_handoff_started
                    and plain_handoff_trigger == "after_third_413_gap"
                    and third_413_seen_at > 0
                    and (time.time() - third_413_seen_at) >= 1.4
                ):
                    _maybe_start_plain_handoff("after_third_413_gap")
                if (
                    controller_auto
                    and auto_controller_enqueued
                    and current_dataenc_key
                    and login_success_seen_at > 0
                    and not saw_data_frame
                    and not auto_retry_582_done
                    and controller_profile != "app_reference_first_6611"
                    and controller_ret_latest is None
                    and (time.time() - login_success_seen_at) >= 1.5
                    and runtime_session_id_live > 0
                ):
                    retry_plain_582 = build_opmonitor_media_plaintext(
                        action="Start",
                        channel=int(channel),
                        stream_type=stream_type or "Main",
                        trans_mode=trans_mode or "TCP",
                        combine_mode=combine_mode or "CONNECT_ALL",
                        session_id_mode="random32",
                        include_channel=True,
                        include_combine_mode=True,
                        include_stream_type=True,
                        include_trans_mode=True,
                    )
                    retry_582 = build_6611_dataenc_followup(
                        cmd=0x0582,
                        plain_payload_text=retry_plain_582,
                        communicate_key=current_dataenc_key,
                        msg_type=0,
                        session_id=int(runtime_session_id_live),
                        msg_id=int(login_followup_msg_id or 24) + 200,
                        unk=0,
                    )
                    retry_582["send_phase"] = "post_login_auto_retry"
                    retry_582["controller_profile"] = f"{controller_profile}:retry_582"
                    retry_582["plain_payload_text"] = retry_plain_582
                    if not _send_followup_dict(retry_582):
                        end_time = time.time()
                    auto_retry_582_done = True
                if (
                    controller_auto
                    and current_dataenc_key
                    and runtime_session_id_live > 0
                    and not saw_data_frame
                    and not auto_retry_second582_done
                    and controller_ret_latest in {101, 103}
                    and controller_response_seen_at > 0
                    and (time.time() - controller_response_seen_at) >= 1.2
                ):
                    retry_plain_second_582 = build_opmonitor_media_plaintext(
                        action="Start",
                        channel=int(channel),
                        stream_type=stream_type or "Main",
                        trans_mode=trans_mode or "TCP",
                        combine_mode=combine_mode or "CONNECT_ALL",
                        session_id_mode="random32",
                        include_channel=True,
                        include_combine_mode=False,
                        include_stream_type=False,
                        include_trans_mode=False,
                    )
                    retry_second_582 = build_6611_dataenc_followup(
                        cmd=0x0582,
                        plain_payload_text=retry_plain_second_582,
                        communicate_key=current_dataenc_key,
                        msg_type=0,
                        session_id=int(runtime_session_id_live),
                        msg_id=int(login_followup_msg_id or 24) + 216,
                        unk=0,
                    )
                    retry_second_582["send_phase"] = "post_login_auto_retry"
                    retry_second_582["controller_profile"] = f"{controller_profile}:retry_second582"
                    retry_second_582["plain_payload_text"] = retry_plain_second_582
                    if not _send_followup_dict(retry_second_582):
                        end_time = time.time()
                    else:
                        end_time = max(end_time, time.time() + response_drain_seconds)
                    auto_retry_second582_done = True
                    _update_second_success_replay_state()
                if (
                    controller_auto
                    and current_dataenc_key
                    and runtime_session_id_live > 0
                    and not saw_data_frame
                    and not auto_retry_61a_done
                    and controller_ret_latest in {101, 103}
                    and controller_response_seen_at > 0
                    and (time.time() - controller_response_seen_at) >= 1.5
                ):
                    retry_61a = build_6611_dataenc_followup(
                        cmd=0x061A,
                        plain_payload_text=build_media_force_iframe_plaintext(int(runtime_session_id_live)),
                        communicate_key=current_dataenc_key,
                        msg_type=0,
                        session_id=int(runtime_session_id_live),
                        msg_id=int(login_followup_msg_id or 24) + 208,
                        unk=256,
                    )
                    retry_61a["send_phase"] = "post_login_auto_retry"
                    retry_61a["controller_profile"] = f"{controller_profile}:retry_61a"
                    retry_61a["plain_payload_text"] = build_media_force_iframe_plaintext(int(runtime_session_id_live))
                    if not _send_followup_dict(retry_61a):
                        end_time = time.time()
                    else:
                        end_time = max(end_time, time.time() + response_drain_seconds)
                    auto_retry_61a_done = True
                    _update_second_success_replay_state()
                if followup_frames and frames and not response_gated_followups:
                    if not _followup_wait_satisfied(followup_frames[0]):
                        followup_next_due_at = time.time() + 0.1
                        end_time = max(end_time, time.time() + response_drain_seconds)
                        continue
                    _schedule_followup_window()
                    if followup_frames and time.time() >= followup_next_due_at:
                        followup = followup_frames[0]
                        burst_group = str(followup.get("burst_group") or "").strip()
                        sent_in_batch = 0
                        if burst_group:
                            grouped_followups = [followup]
                            next_index = 1
                            while next_index < len(followup_frames):
                                candidate = followup_frames[next_index]
                                if str(candidate.get("burst_group") or "").strip() != burst_group:
                                    break
                                grouped_followups.append(candidate)
                                next_index += 1
                            send_ok = _send_followup_batch(grouped_followups)
                            if send_ok:
                                del followup_frames[:next_index]
                                sent_in_batch = len(grouped_followups)
                        else:
                            send_ok = _send_followup_dict(followup)
                            if send_ok:
                                del followup_frames[:1]
                                sent_in_batch = 1
                        if not send_ok:
                            end_time = time.time()
                            followup_frames = []
                            followup_schedule_started_at = 0.0
                            followup_next_due_at = 0.0
                        else:
                            if sent_in_batch >= 1 and (
                                login_followup_builder is None
                                or login_success_seen_at > 0
                                or post_login_followups_queued
                            ):
                                _maybe_start_plain_handoff("after_first_followup")
                                end_time = max(end_time, time.time() + response_drain_seconds)
                            if followup_frames:
                                followup_next_due_at = time.time() + max(
                                    0.0,
                                    float(followup_frames[0].get("delay_before") or 0.0),
                                )
                            else:
                                followup_schedule_started_at = 0.0
                                followup_next_due_at = 0.0
                if (
                    controller_keepalive_interval > 0
                    and current_dataenc_key
                    and runtime_session_id_live > 0
                    and plain_handoff_live_data_seen.is_set()
                    and not (stop_event is not None and stop_event.is_set())
                ):
                    now = time.time()
                    if controller_keepalive_next_at <= 0:
                        controller_keepalive_next_at = now + controller_keepalive_interval
                        end_time = max(end_time, controller_keepalive_next_at + controller_keepalive_grace)
                    elif now >= controller_keepalive_next_at:
                        keepalive_plain = build_named_session_plaintext(
                            "KeepAlive",
                            session_id=int(runtime_session_id_live),
                        )
                        keepalive_followup = build_6611_dataenc_followup(
                            cmd=0x03EE,
                            plain_payload_text=keepalive_plain,
                            communicate_key=current_dataenc_key,
                            msg_type=0,
                            session_id=int(runtime_session_id_live),
                            msg_id=0,
                            unk=0,
                        )
                        keepalive_followup["send_phase"] = "controller_keepalive"
                        keepalive_followup["controller_profile"] = controller_profile
                        keepalive_followup["plain_payload_text"] = keepalive_plain
                        if not _send_followup_dict(keepalive_followup):
                            end_time = time.time()
                        else:
                            controller_keepalive_sent += 1
                if (
                    plain_handoff_pending
                    and not plain_handoff_started
                    and not followup_frames
                    and (
                        login_followup_builder is None
                        or login_success_seen_at > 0
                        or post_login_followups_queued
                    )
                ):
                    _maybe_start_plain_handoff("after_first_followup")

                if response_gated_followups_release_pending:
                    response_gated_followups = False
                    response_gated_followups_release_pending = False

            if plain_handoff_thread is not None:
                if plain_handoff_live_data_seen.is_set():
                    while plain_handoff_thread.is_alive() and not (stop_event is not None and stop_event.is_set()):
                        plain_handoff_thread.join(timeout=0.5)
                else:
                    plain_handoff_thread.join(timeout=plain_handoff_join_timeout)
                if plain_handoff_thread.is_alive() and not plain_handoff_live_data_seen.is_set():
                    plain_handoff_async_result.setdefault("plain_handoff_probe", {})
                    probe_info = plain_handoff_async_result.get("plain_handoff_probe")
                    if not isinstance(probe_info, dict):
                        probe_info = {}
                        plain_handoff_async_result["plain_handoff_probe"] = probe_info
                    probe_info.setdefault("status", "timeout")
                    probe_info.setdefault("error", "plain_handoff_thread_timeout")
                if plain_handoff_async_result.get("plain_handoff_agent_http"):
                    result["plain_handoff_agent_http"] = plain_handoff_async_result.get("plain_handoff_agent_http") or {}
                if plain_handoff_async_result.get("plain_handoff_agent_server"):
                    result["plain_handoff_agent_server"] = plain_handoff_async_result.get("plain_handoff_agent_server") or {}
                if plain_handoff_async_result.get("plain_handoff_probe"):
                    result["plain_handoff_probe"] = plain_handoff_async_result.get("plain_handoff_probe") or {}
                if plain_handoff_async_result.get("plain_handoff_runs"):
                    result["plain_handoff_runs"] = list(plain_handoff_async_result.get("plain_handoff_runs") or [])

            result["claim"] = {
                "sent": {
                    "session_id": session_int,
                    "session_hex": session_hex,
                    "msg_id": msg_id,
                    "unk": unk,
                    "cmd": cmd,
                    "payload_len": len(payload),
                    "claim_random_a": claim_random_a,
                }
            }
            result["agent_random_str"] = xor_key
            result["media_random_str"] = current_media_random_str or None
            result["vekey1"] = current_vekey1 or None
            if built_login_summary:
                result["claim"]["built_login"] = built_login_summary
            if sent_followups:
                result["claim"]["followups"] = sent_followups
            if controller_keepalive_interval > 0:
                result["claim"]["controller_keepalive"] = {
                    "interval": controller_keepalive_interval,
                    "recurring_sent": controller_keepalive_sent,
                    "next_at": controller_keepalive_next_at or None,
                }
            if followup_send_error:
                result["claim"]["followup_send_error"] = followup_send_error
            if recv_error:
                result["claim"]["recv_error"] = recv_error
            if controller_auto:
                result["claim"]["controller_auto"] = {
                    "enabled": True,
                    "profile": controller_profile,
                    "enqueued": auto_controller_enqueued,
                }
            if dynamic_followup_queue is not None:
                result["claim"]["dynamic_followups"] = {
                    "queued": dynamic_followups_enqueued,
                    "sent": dynamic_followups_sent,
                    "pending": len(dynamic_followup_frames),
                }
            if plain_handoff_config:
                result["claim"]["plain_handoff_trigger"] = plain_handoff_trigger
                result["claim"]["second_success_replay_state"] = second_success_replay_state
                if second_success_replay_seen_at > 0:
                    result["claim"]["second_success_replay_seen_at"] = second_success_replay_seen_at
            cmd_counts = Counter(f"0x{frame_item.cmd:04x}" for frame_item in frames)
            claim_response = next((item for item in frames if item.msg_type == 0 and item.cmd == (cmd + 1)), None)
            claim_response_summary: dict[str, Any] = {}
            if claim_response is not None:
                claim_response_summary = _summarize_tcp_frame(
                    claim_response,
                    dataenc_key=current_dataenc_key,
                    not_encrypt_cmds=current_not_encrypt_cmds,
                )
            if claim_response_summary:
                result["claim"]["response"] = claim_response_summary
            frame_summaries: list[dict[str, Any]] = []
            for frame_item in frames[:20]:
                frame_summaries.append(
                    _summarize_tcp_frame(
                        frame_item,
                        dataenc_key=current_dataenc_key,
                        not_encrypt_cmds=current_not_encrypt_cmds,
                    )
                )
            control_frame_summaries: list[dict[str, Any]] = []
            data_frame_summaries: list[dict[str, Any]] = []
            for frame_item in frames:
                frame_summary = _summarize_tcp_frame(
                    frame_item,
                    dataenc_key=current_dataenc_key,
                    not_encrypt_cmds=current_not_encrypt_cmds,
                    include_payload_b64=(frame_item.msg_type == 1 and len(data_frame_summaries) < MEDIA_PAYLOAD_B64_LIMIT),
                )
                if frame_item.msg_type == 0:
                    control_frame_summaries.append(frame_summary)
                elif frame_item.msg_type == 1:
                    data_frame_summaries.append(frame_summary)

            result["frames"] = {
                "total": len(frames),
                "control": len([f for f in frames if f.msg_type == 0]),
                "data": len([f for f in frames if f.msg_type == 1]),
                "cmd_counts": dict(sorted(cmd_counts.items())),
                "first_frames": frame_summaries,
                "control_frames": control_frame_summaries,
                "data_frames": data_frame_summaries[:MEDIA_FRAME_SUMMARY_LIMIT],
                "raw_total_bytes": len(received),
                "decoded_total_bytes": len(decoded_stream),
                "decoded_head_hex": bytes(decoded_stream[:128]).hex(),
                "decoded_tail_hex": bytes(decoded_stream[-128:]).hex(),
            }
            controller_status = ""
            for frame_summary in control_frame_summaries:
                if int(_intish(frame_summary.get("cmd"), 0)) == 0x0583:
                    controller_status = _classify_media_control_ret(_intish(_frame_json_payload(frame_summary).get("Ret"), None))
            result["local_bootstrap_summary"] = analyze_local_media_bootstrap_frames(
                frames,
                random_str=xor_key,
                media_random_str=current_media_random_str,
                vekey1=current_vekey1,
                controller_status=controller_status,
            )
            if recv_error:
                result["error"] = recv_error
            result["status"] = "ok" if frames else "partial"
            return result
        finally:
            sock.close()


class RpsLiveChain:
    def __init__(
        self,
        *,
        status_base: str = DEFAULT_STATUS_BASE,
        status_user_agent: str = DEFAULT_STATUS_UA,
        status_content_type: str = "text/html",
        status_ssl_verify: bool = False,
        agent_ssl_verify: bool = False,
    ) -> None:
        self.status_base = status_base
        self.status_user_agent = status_user_agent
        self.status_content_type = status_content_type
        self.status_ssl_verify = status_ssl_verify
        self.agent_ssl_verify = agent_ssl_verify

    def _pick_status_entry(self, body: list[Any], serial_number: str) -> dict[str, Any]:
        for item in body:
            if not isinstance(item, dict):
                continue
            if str(item.get("SerialNumber") or "").strip() == serial_number:
                return item
        return body[0] if body and isinstance(body[0], dict) else {}

    def run(
        self,
        *,
        serial_number: str,
        authcode: str,
        status_server_ip: str = "",
        status_server_port: str = "",
        client_token: str,
        session_id: str,
        dest_port: str,
        service_type: str,
        encrypt: str,
        step: str,
        protocol_mode: str,
        vendor: str = "",
        developer_id: str = "",
        app_key: str = "",
        timeout: int,
        channel: int,
        stream_type: str,
        trans_mode: str,
        combine_mode: str,
        msg_id: int,
        code: int,
        code_endian: str,
        capture_seconds: float,
        max_frames: int,
        tcp_mode: str = "plain",
        encrypted_session_int: int = 0x1869F,
        encrypted_msg_id: int = 0x10,
        encrypted_unk: int = 0x63,
        encrypted_cmd: int = 0x0585,
        encrypted_claim_random_a: str = "",
        encrypted_session_hex_width: int = 10,
        encrypted_stream_type: str = "Main",
        encrypted_combine_mode: str = "CONNECT_ALL",
        encrypted_trans_mode: str = "TCP",
        encrypted_followup_frames: list[dict[str, Any]] | None = None,
        encrypted_followup_delay: float = 0.0,
        encrypted_login_followup: dict[str, Any] | None = None,
        encrypted_controller_auto: bool = False,
        encrypted_controller_profile: str = "historical_order_built_queries_dynamic_second582",
        plain_handoff: bool = False,
        plain_handoff_trigger: str = "after_second_413",
        plain_handoff_stream_type: str = "Extra1",
        plain_handoff_initial_payload_text: str = "",
        plain_handoff_initial_code: int | None = None,
        plain_handoff_claim_replay_count: int | None = None,
        gwm_ams_url: str = "",
        device_oem_id: str = "",
        device_hardware: str = "",
        device_idr_auto_wakeup: bool = False,
        wakeup_probe_enabled: bool = True,
        wakeup_host: str = "",
        wakeup_port: int = 0,
        runtime_mode: str = "baseline_20260323",
        stop_event: threading.Event | None = None,
        plain_handoff_data_frame_callback: Callable[[bytes, str], None] | None = None,
        plain_handoff_extend_on_activity: bool = False,
        dynamic_followup_queue: Any | None = None,
        progress_callback: Callable[[str], None] | None = None,
        include_agent_response_metadata: bool = False,
    ) -> dict[str, Any]:
        normalized_runtime_mode = str(runtime_mode or "baseline_20260323").strip() or "baseline_20260323"
        baseline_runtime = normalized_runtime_mode == "baseline_20260323"
        result: dict[str, Any] = {
            "status": "error",
            "runtime_mode": normalized_runtime_mode,
            "status_query": {},
            "agent_http": {},
            "agent_server": {},
            "tcp_mode": tcp_mode,
            "tcp_probe": {},
            "tcp_encrypted_probe": {},
            "plain_handoff_agent_http": {},
            "plain_handoff_agent_server": {},
            "tcp_plain_handoff_probe": {},
            "plain_handoff_runs": [],
            "idr_status_probe": {},
            "wakeup_probe": {},
            "gwm_probe": {},
            "gwm_probe_after_wakeup": {},
            "device_idr_auto_wakeup": bool(device_idr_auto_wakeup),
        }

        def _emit_progress(detail: str) -> None:
            if progress_callback is not None:
                progress_callback(" ".join(str(detail or "").split()))

        server_ip = str(status_server_ip or "").strip()
        server_port = str(status_server_port or "").strip()
        if server_ip and server_port:
            _emit_progress(f"pub-status response cached {server_ip}:{server_port}")
            result["status_query"] = {
                "ok": True,
                "status": None,
                "url": "direct-server-override",
                "parsed": {
                    "message_type": "DIRECT_OVERRIDE",
                    "error_num": "200",
                    "error_string": "Skipped pub-status and used explicit server",
                    "body": [
                        {
                            "SerialNumber": serial_number,
                            "ServerIP": server_ip,
                            "ServerPort": server_port,
                            "Status": "Bypassed",
                        }
                    ],
                },
                "error": None,
            }
        else:
            _emit_progress("pub-status request")
            status_res = status_protocol_query(
                serial_number=serial_number,
                authcode=authcode,
                base=self.status_base,
                timeout=timeout,
                ssl_verify=self.status_ssl_verify,
                user_agent=self.status_user_agent,
                content_type=self.status_content_type,
            )
            status_parsed = parse_status_protocol_response(status_res.json_data)
            _emit_progress(f"pub-status response http={status_res.status or 'none'} ok={bool(status_res.ok)}")
            result["status_query"] = {
                "ok": status_res.ok,
                "status": status_res.status,
                "url": status_res.url,
                "parsed": status_parsed,
                "error": status_res.error,
            }
            if not status_res.ok or not status_parsed:
                return result

            entry = self._pick_status_entry(status_parsed.get("body", []), serial_number)
            server_ip = str(entry.get("ServerIP") or "").strip()
            server_port = str(entry.get("ServerPort") or "").strip()

        should_probe_idr_early = bool(plain_handoff or (wakeup_probe_enabled and not baseline_runtime))
        if should_probe_idr_early:
            try:
                _emit_progress("IDR status request")
                result["idr_status_probe"] = run_idr_status_probe(
                    serial_number=serial_number,
                    authcode=authcode,
                    manufacturer_candidates=[
                        device_oem_id,
                        device_hardware,
                        vendor,
                    ],
                    timeout=min(timeout, 12),
                    user_agent=self.status_user_agent,
                    ssl_verify=self.agent_ssl_verify,
                    content_types=[self.status_content_type],
                )
                _emit_progress(f"IDR status response {result['idr_status_probe'].get('status') or 'unknown'}")
            except Exception as exc:  # noqa: BLE001
                _emit_progress("IDR status response error")
                result["idr_status_probe"] = {
                    "status": "error",
                    "error": f"idr_probe_failed: {exc}",
                }
        if (not server_ip or not server_port) and isinstance(result.get("idr_status_probe"), dict):
            idr_entry = (
                (result.get("idr_status_probe") or {}).get("entry")
                if isinstance((result.get("idr_status_probe") or {}).get("entry"), dict)
                else {}
            )
            idr_server_ip = str(idr_entry.get("ServerIP") or "").strip()
            idr_server_port = str(idr_entry.get("ServerPort") or "").strip()
            if idr_server_ip and idr_server_port:
                server_ip = idr_server_ip
                server_port = idr_server_port
                result["status_query"]["server_fallback"] = {
                    "source": "idr_status_probe",
                    "server_ip": server_ip,
                    "server_port": server_port,
                    "status": str(idr_entry.get("Status") or "").strip(),
                    "dev_status": idr_entry.get("DevStatus"),
                    "wake_up_enable": idr_entry.get("WakeUpEnable"),
                }
        if not server_ip or not server_port:
            return result

        agent_payload = build_agent_protocol_payload(
            authcode=authcode,
            serial_number=serial_number,
            client_token=client_token,
            dest_port=dest_port,
            service_type=service_type,
            session_id=session_id,
            encrypt=encrypt,
            step=step,
            protocol_mode=protocol_mode,
            vendor=vendor,
        )
        agent_payloads = build_agent_payload_variants(
            authcode=authcode,
            serial_number=serial_number,
            client_token=client_token,
            dest_port=dest_port,
            service_type=service_type,
            session_id=session_id,
            encrypt=encrypt,
            step=step,
            protocol_mode=protocol_mode,
            vendor=vendor,
        )
        agent_urls = _dedupe(
            [
                f"https://{server_ip}:{server_port}/",
            ]
        )
        agent_content_types = _dedupe(
            [
                self.status_content_type,
                "text/html",
                "application/json",
            ]
        )

        agent_attempts: list[dict[str, Any]] = []
        agent_pick: dict[str, Any] = {}
        for agent_payload in agent_payloads:
            payload_body = agent_payload.get("AgentProtocol", {}).get("Body", {})
            for agent_url in agent_urls:
                for content_type in agent_content_types:
                    service_label = str(payload_body.get("ServiceType") or service_type or "AgentProtocol")
                    _emit_progress(f"AgentProtocol request {service_label} {content_type}")
                    agent_res = agent_protocol_query(
                        url=agent_url,
                        payload=agent_payload,
                        timeout=timeout,
                        ssl_verify=self.agent_ssl_verify if agent_url.startswith("https://") else False,
                        user_agent=self.status_user_agent,
                        content_type=content_type,
                        runtime_mode=normalized_runtime_mode,
                    )
                    agent_parsed = parse_agent_protocol_response(agent_res.json_data)
                    relay = ""
                    if agent_parsed.get("agent_server_ip") and agent_parsed.get("agent_server_port"):
                        relay = f" relay={agent_parsed.get('agent_server_ip')}:{agent_parsed.get('agent_server_port')}"
                    _emit_progress(f"AgentProtocol response http={agent_res.status or 'none'} ok={bool(agent_res.ok)}{relay}")
                    attempt = {
                        "ok": agent_res.ok,
                        "status": agent_res.status,
                        "url": agent_res.url,
                        "content_type": content_type,
                        "service_type": payload_body.get("ServiceType"),
                        "parsed": agent_parsed,
                        "response_diagnostics": summarize_agent_response(
                            agent_res.json_data, request_payload=agent_payload, transport_error=agent_res.error,
                        ),
                        "response_head": (agent_res.text or "")[:400],
                        "error": agent_res.error,
                    }
                    agent_attempts.append(attempt)
                    if include_agent_response_metadata:
                        _emit_progress('AgentProtocol response metadata ' + json.dumps(
                            attempt['response_diagnostics'], ensure_ascii=False, separators=(',', ':'),
                        ))
                    if agent_parsed.get("agent_server_ip") and agent_parsed.get("agent_server_port"):
                        agent_pick = attempt
                        break
                if agent_pick:
                    break
            if agent_pick:
                break

        result["agent_http"] = {
            "selected": agent_pick,
            "attempts": agent_attempts,
        }
        agent_parsed = agent_pick.get("parsed") if isinstance(agent_pick.get("parsed"), dict) else {}
        if not agent_parsed.get("agent_server_ip") or not agent_parsed.get("agent_server_port"):
            return result

        result["agent_server"] = {
            "ip": agent_parsed.get("agent_server_ip"),
            "port": int(agent_parsed.get("agent_server_port") or 0),
            "random_str": agent_parsed.get("random_str"),
            "protocol_mode": agent_parsed.get("protocol_mode"),
        }

        probe_statuses: list[str] = []
        agent_host = str(agent_parsed.get("agent_server_ip"))
        agent_port = int(agent_parsed.get("agent_server_port"))
        if tcp_mode in {"plain", "both"}:
            tcp_probe = AgentTcpLiveProbe()
            tcp_result = tcp_probe.run_probe(
                host=agent_host,
                port=agent_port,
                authcode=authcode,
                client_token=client_token,
                serial=serial_number,
                session=session_id,
                session_int=0x78,
                channel=channel,
                stream_type=stream_type,
                trans_mode=trans_mode,
                combine_mode=combine_mode,
                msg_id=msg_id,
                code=code,
                code_endian=code_endian,
                timeout=float(timeout),
                capture_seconds=capture_seconds,
                max_frames=max_frames,
                followup_frames=build_plain_claim_replay_followups(
                    session_int=0x78,
                    channel=channel,
                    stream_type=stream_type,
                    trans_mode=trans_mode,
                    combine_mode=combine_mode,
                    msg_id=msg_id,
                    code=code,
                    code_endian=code_endian,
                ),
                stop_event=stop_event,
            )
            tcp_result["controller_summary"] = analyze_live_controller_flow(tcp_result)
            tcp_result["local_bootstrap_summary"] = _ensure_local_bootstrap_summary(
                tcp_result,
                controller_status=str((tcp_result.get("controller_summary") or {}).get("status") or ""),
                media_random_str=str(tcp_result.get("media_random_str") or ""),
                vekey1=str(tcp_result.get("vekey1") or ""),
            )
            result["tcp_probe"] = tcp_result
            probe_statuses.append(str(tcp_result.get("status") or ""))

        if tcp_mode in {"encrypted", "both"}:
            random_str = str(agent_parsed.get("random_str") or "")
            if random_str:
                enc_probe = AgentTcpEncryptedClaimProbe()
                control_bind_proxy: LocalAgentTcpBindProxy | LocalAgentSdkBindProxy | None = None
                plain_claim_replay_count_default = 0
                plain_claim_replay_count_env = str(os.environ.get("ICSEE_PLAIN_CLAIM_REPLAY_COUNT") or "").strip()
                if plain_claim_replay_count_env:
                    try:
                        plain_claim_replay_count_default = max(0, min(8, int(plain_claim_replay_count_env)))
                    except ValueError:
                        plain_claim_replay_count_default = 0
                integrated_plain_handoff = {
                    "status_server_ip": server_ip,
                    "status_server_port": server_port,
                    "dest_port": dest_port,
                    "service_type": "",
                    "encrypt": encrypt,
                    "step": "",
                    "protocol_mode": protocol_mode,
                    "vendor": vendor,
                    "developer_id": developer_id,
                    "app_key": app_key,
                    "user_agent": self.status_user_agent,
                    "content_type": self.status_content_type,
                    "agent_ssl_verify": self.agent_ssl_verify,
                    "selector_timeout": min(timeout, 15),
                    "probe_timeout": min(float(timeout), 12.0),
                    "rounds": 1,
                    "start_trigger": plain_handoff_trigger,
                    "stream_type": str(plain_handoff_stream_type or "Extra1"),
                    "initial_payload_text": str(plain_handoff_initial_payload_text or ""),
                    "initial_code": plain_handoff_initial_code,
                    "prepare_early": True,
                    "prepare_stage": "after_login",
                    "prime_selector_early": True,
                    "bind_proxy_mode": "tcp_bind_proxy",
                    "recreate_bind_on_start": plain_handoff_trigger == "after_second_success_replay",
                    "reuse_outer_session_id": False,
                    "claim_replay_count": (
                        plain_claim_replay_count_default
                        if plain_handoff_claim_replay_count is None
                        else max(0, int(plain_handoff_claim_replay_count))
                    ),
                    "claim_replay_delay": 0.35,
                    "claim_replay_delay_step": 0.45,
                    "claim_replay_msgid_step": 1,
                    "use_control_bind": False,
                } if plain_handoff else None
                selector_attempt_runs: list[dict[str, Any]] = []
                max_rpscmd_attempts = (
                    24 if (not baseline_runtime and str(service_type or "").strip() == "RpsCmd") else 1
                )
                rotate_client_token_on_retry = str(
                    os.environ.get("ICSEE_ROTATE_AGENT_CLIENT_ON_RETRY") or "0"
                ).strip().lower() not in {"0", "false", "no", "off"}
                env_rpscmd_attempts = str(os.environ.get("ICSEE_RPSCMD_MAX_ATTEMPTS") or "").strip()
                if env_rpscmd_attempts:
                    try:
                        max_rpscmd_attempts = max(1, min(64, int(env_rpscmd_attempts)))
                    except ValueError:
                        pass
                best_enc_result: dict[str, Any] = {}
                best_selector_pick: dict[str, Any] = {}
                best_agent_server: dict[str, Any] = {}
                best_score = -1

                def _score_encrypted_attempt(enc_attempt_result: dict[str, Any]) -> int:
                    frames_info = (enc_attempt_result.get("frames") or {}) if isinstance(enc_attempt_result, dict) else {}
                    handshake_info = (enc_attempt_result.get("handshake") or {}) if isinstance(enc_attempt_result, dict) else {}
                    control_count = _intish(frames_info.get("control"), 0)
                    data_count = _intish(frames_info.get("data"), 0)
                    handshake_ok = bool(handshake_info.get("ok"))
                    return (1000 if data_count > 0 else 0) + (100 if control_count > 0 else 0) + (10 if handshake_ok else 0)

                def _is_encrypted_attempt_alive(enc_attempt_result: dict[str, Any]) -> bool:
                    frames_info = (enc_attempt_result.get("frames") or {}) if isinstance(enc_attempt_result, dict) else {}
                    return _intish(frames_info.get("control"), 0) > 0 or _intish(frames_info.get("data"), 0) > 0

                current_pick = agent_pick
                current_parsed = agent_parsed
                current_session_id = session_id
                current_client_token = client_token

                for enc_attempt_index in range(max_rpscmd_attempts):
                    if enc_attempt_index > 0:
                        current_session_id = build_session_id()
                        current_client_token = build_client_token() if rotate_client_token_on_retry else client_token
                        retry_payloads = build_agent_payload_variants(
                            authcode=authcode,
                            serial_number=serial_number,
                            client_token=current_client_token,
                            dest_port=dest_port,
                            service_type=service_type,
                            session_id=current_session_id,
                            encrypt=encrypt,
                            step=step,
                            protocol_mode=protocol_mode,
                            vendor=vendor,
                        )
                        retry_attempts: list[dict[str, Any]] = []
                        retry_pick: dict[str, Any] = {}
                        for retry_payload in retry_payloads:
                            payload_body = retry_payload.get("AgentProtocol", {}).get("Body", {})
                            for agent_url in agent_urls:
                                for content_type in agent_content_types:
                                    service_label = str(payload_body.get("ServiceType") or service_type or "AgentProtocol")
                                    _emit_progress(f"AgentProtocol retry request {enc_attempt_index + 1} {service_label} {content_type}")
                                    retry_res = agent_protocol_query(
                                        url=agent_url,
                                        payload=retry_payload,
                                        timeout=timeout,
                                        ssl_verify=self.agent_ssl_verify if agent_url.startswith("https://") else False,
                                        user_agent=self.status_user_agent,
                                        content_type=content_type,
                                        runtime_mode=normalized_runtime_mode,
                                    )
                                    retry_parsed = parse_agent_protocol_response(retry_res.json_data)
                                    relay = ""
                                    if retry_parsed.get("agent_server_ip") and retry_parsed.get("agent_server_port"):
                                        relay = f" relay={retry_parsed.get('agent_server_ip')}:{retry_parsed.get('agent_server_port')}"
                                    _emit_progress(f"AgentProtocol retry response {enc_attempt_index + 1} http={retry_res.status or 'none'} ok={bool(retry_res.ok)}{relay}")
                                    retry_attempt = {
                                        "ok": retry_res.ok,
                                        "status": retry_res.status,
                                        "url": retry_res.url,
                                        "content_type": content_type,
                                        "service_type": payload_body.get("ServiceType"),
                                        "parsed": retry_parsed,
                                        "response_diagnostics": summarize_agent_response(
                                            retry_res.json_data, request_payload=retry_payload,
                                            transport_error=retry_res.error,
                                        ),
                                        "response_head": (retry_res.text or "")[:400],
                                        "error": retry_res.error,
                                        "selector_attempt_index": enc_attempt_index + 1,
                                        "session_id_masked": _mask_secret(current_session_id, 6, 4),
                                        "client_token_masked": _mask_secret(current_client_token, 8, 4),
                                    }
                                    agent_attempts.append(retry_attempt)
                                    retry_attempts.append(retry_attempt)
                                    if include_agent_response_metadata:
                                        _emit_progress('AgentProtocol response metadata ' + json.dumps(
                                            retry_attempt['response_diagnostics'], ensure_ascii=False, separators=(',', ':'),
                                        ))
                                    if retry_parsed.get("agent_server_ip") and retry_parsed.get("agent_server_port"):
                                        retry_pick = retry_attempt
                                        break
                                if retry_pick:
                                    break
                            if retry_pick:
                                break
                        current_pick = retry_pick
                        current_parsed = retry_pick.get("parsed") if isinstance(retry_pick.get("parsed"), dict) else {}
                        selector_attempt_runs.append(
                            {
                                "selector_attempt_index": enc_attempt_index + 1,
                                "session_id_masked": _mask_secret(current_session_id, 6, 4),
                                "client_token_masked": _mask_secret(current_client_token, 8, 4),
                                "agent_http": {
                                    "selected": retry_pick,
                                    "attempts": retry_attempts,
                                },
                            }
                        )
                        if not current_parsed.get("agent_server_ip") or not current_parsed.get("agent_server_port"):
                            continue

                    current_random_str = str(current_parsed.get("random_str") or "")
                    if not current_random_str:
                        continue
                    enc_host = str(current_parsed.get("agent_server_ip") or "")
                    enc_port = int(current_parsed.get("agent_server_port") or 0)
                    if not enc_host or enc_port <= 0:
                        continue

                    control_bind_summary: dict[str, Any] = {}
                    enc_skip_handshake = False
                    use_control_bind = bool((integrated_plain_handoff or {}).get("use_control_bind"))
                    if use_control_bind:
                        control_bind_proxy = LocalAgentTcpBindProxy(
                            upstream_host=enc_host,
                            upstream_port=enc_port,
                            authcode=authcode,
                            client_token=current_client_token,
                            serial=serial_number,
                            session=current_session_id,
                            random_str="",
                            timeout=min(float(timeout), 12.0),
                        )
                        control_bind_proxy.start()
                        enc_host = control_bind_proxy.local_host
                        enc_port = control_bind_proxy.local_port
                        enc_skip_handshake = True
                    try:
                        enc_result = enc_probe.run_probe(
                            host=enc_host,
                            port=enc_port,
                            authcode=authcode,
                            client_token=current_client_token,
                            serial=serial_number,
                            session=current_session_id,
                            xor_key=current_random_str,
                            claim_random_a=encrypted_claim_random_a or build_session_id(4),
                            session_int=encrypted_session_int,
                            channel=channel,
                            stream_type=encrypted_stream_type,
                            trans_mode=encrypted_trans_mode,
                            combine_mode=encrypted_combine_mode,
                            msg_id=encrypted_msg_id,
                            unk=encrypted_unk,
                            cmd=encrypted_cmd,
                            timeout=float(timeout),
                            capture_seconds=capture_seconds,
                            max_frames=max_frames,
                            session_hex_width=encrypted_session_hex_width,
                            followup_frames=encrypted_followup_frames,
                            followup_delay=encrypted_followup_delay,
                            login_followup_builder=encrypted_login_followup,
                            controller_auto=encrypted_controller_auto,
                            controller_profile=encrypted_controller_profile,
                            plain_handoff_config=integrated_plain_handoff,
                            skip_handshake=enc_skip_handshake,
                            stop_event=stop_event,
                            plain_handoff_data_frame_callback=plain_handoff_data_frame_callback,
                            plain_handoff_extend_on_activity=plain_handoff_extend_on_activity,
                            dynamic_followup_queue=dynamic_followup_queue,
                            progress_callback=progress_callback,
                        )
                        if control_bind_proxy is not None:
                            control_bind_summary = control_bind_proxy.summary()
                    finally:
                        if control_bind_proxy is not None:
                            control_bind_proxy.close()
                            control_bind_proxy = None
                    if control_bind_summary:
                        enc_result["control_bind"] = control_bind_summary
                    enc_result["controller_summary"] = analyze_live_controller_flow(enc_result)
                    enc_result["selector_attempt_index"] = enc_attempt_index + 1
                    enc_result["selector_session_id_masked"] = _mask_secret(current_session_id, 6, 4)
                    attempt_score = _score_encrypted_attempt(enc_result)
                    selector_attempt_runs.append(
                        {
                            "selector_attempt_index": enc_attempt_index + 1,
                            "session_id_masked": _mask_secret(current_session_id, 6, 4),
                            "client_token_masked": _mask_secret(current_client_token, 8, 4),
                            "agent_http": {
                                "selected": current_pick,
                            },
                            "agent_server": {
                                "ip": current_parsed.get("agent_server_ip"),
                                "port": int(current_parsed.get("agent_server_port") or 0),
                                "random_str": current_random_str,
                                "protocol_mode": current_parsed.get("protocol_mode"),
                            },
                            "probe_status": str(enc_result.get("status") or ""),
                            "handshake_ok": bool(((enc_result.get("handshake") or {}).get("ok"))),
                            "frames": dict(enc_result.get("frames") or {}),
                        }
                    )
                    if attempt_score > best_score:
                        best_score = attempt_score
                        best_enc_result = enc_result
                        best_selector_pick = current_pick
                        best_agent_server = {
                            "ip": current_parsed.get("agent_server_ip"),
                            "port": int(current_parsed.get("agent_server_port") or 0),
                            "random_str": current_random_str,
                            "protocol_mode": current_parsed.get("protocol_mode"),
                        }
                        best_agent_server["client_token"] = current_client_token
                    if _is_encrypted_attempt_alive(enc_result):
                        if current_client_token != client_token:
                            _set_agent_client_uuid(current_client_token)
                        break

                if best_selector_pick:
                    result["agent_http"]["selected"] = best_selector_pick
                if best_agent_server:
                    best_client_token = str(best_agent_server.pop("client_token", "") or "")
                    if best_client_token and best_client_token != client_token and best_score > 0:
                        _set_agent_client_uuid(best_client_token)
                        result["agent_client_token_rotated"] = True
                        result["agent_client_token_masked"] = _mask_secret(best_client_token, 8, 4)
                    result["agent_server"] = best_agent_server
                if selector_attempt_runs and not baseline_runtime:
                    result["agent_http"]["rpscmd_retry_attempts"] = selector_attempt_runs
                enc_result = best_enc_result
                if enc_result:
                    result["tcp_encrypted_probe"] = enc_result
                    if enc_result.get("plain_handoff_agent_http"):
                        result["plain_handoff_agent_http"] = enc_result.get("plain_handoff_agent_http") or {}
                    if enc_result.get("plain_handoff_agent_server"):
                        result["plain_handoff_agent_server"] = enc_result.get("plain_handoff_agent_server") or {}
                    if enc_result.get("plain_handoff_probe"):
                        result["tcp_plain_handoff_probe"] = enc_result.get("plain_handoff_probe") or {}
                    if enc_result.get("plain_handoff_runs"):
                        result["plain_handoff_runs"] = list(enc_result.get("plain_handoff_runs") or [])
                    probe_statuses.append(str(enc_result.get("status") or ""))
            else:
                result["tcp_encrypted_probe"] = {
                    "status": "error",
                    "error": "random_str_missing",
                }
                probe_statuses.append("error")

        handoff_status = str((((result.get("tcp_encrypted_probe") or {}).get("controller_summary") or {}).get("status")) or "")
        fallback_plain_session_int = 0x78
        encrypted_controller_summary = (
            ((result.get("tcp_encrypted_probe") or {}).get("controller_summary") or {})
            if isinstance((result.get("tcp_encrypted_probe") or {}).get("controller_summary"), dict)
            else {}
        )
        encrypted_controller_signals = (
            encrypted_controller_summary.get("signals")
            if isinstance(encrypted_controller_summary.get("signals"), dict)
            else {}
        )
        for candidate_session in (
            encrypted_controller_summary.get("session_id_after_login"),
            encrypted_controller_summary.get("runtime_session"),
            encrypted_controller_signals.get("session_id_after_login"),
        ):
            if not candidate_session:
                continue
            try:
                fallback_plain_session_int = int(str(candidate_session), 0)
                break
            except Exception:
                continue
        existing_handoff_probe = result.get("tcp_plain_handoff_probe") or {}
        if (
            plain_handoff
            and handoff_status == "controller_readying"
            and not result.get("plain_handoff_runs")
            and not existing_handoff_probe
        ):
            handoff_probe_timeout = min(float(timeout), 12.0)
            handoff_rounds = 1
            best_handoff_attempt: dict[str, Any] = {}
            best_handoff_server: dict[str, Any] = {}
            best_handoff_probe: dict[str, Any] = {}
            best_handoff_score = -1
            for handoff_round in range(1, handoff_rounds + 1):
                handoff_client_token = client_token
                handoff_session_id = build_session_id()
                handoff_payloads = build_agent_payload_variants(
                    authcode=authcode,
                    serial_number=serial_number,
                    client_token=handoff_client_token,
                    dest_port=dest_port,
                    service_type="RpsAV",
                    session_id=handoff_session_id,
                    encrypt=encrypt,
                    step="8",
                    protocol_mode=protocol_mode,
                    vendor=vendor,
                )
                handoff_attempts: list[dict[str, Any]] = []
                handoff_pick: dict[str, Any] = {}
                for handoff_payload in handoff_payloads:
                    payload_body = handoff_payload.get("AgentProtocol", {}).get("Body", {})
                    for agent_url in agent_urls:
                        for content_type in agent_content_types:
                            handoff_res = agent_protocol_query(
                                url=agent_url,
                                payload=handoff_payload,
                                timeout=min(timeout, 15),
                                ssl_verify=self.agent_ssl_verify if agent_url.startswith("https://") else False,
                                user_agent=self.status_user_agent,
                                content_type=content_type,
                                runtime_mode=normalized_runtime_mode,
                            )
                            handoff_parsed = parse_agent_protocol_response(handoff_res.json_data)
                            attempt = {
                                "ok": handoff_res.ok,
                                "status": handoff_res.status,
                                "url": handoff_res.url,
                                "content_type": content_type,
                                "service_type": payload_body.get("ServiceType"),
                                "parsed": handoff_parsed,
                                "response_head": (handoff_res.text or "")[:400],
                                "error": handoff_res.error,
                            }
                            handoff_attempts.append(attempt)
                            if handoff_parsed.get("agent_server_ip") and handoff_parsed.get("agent_server_port"):
                                handoff_pick = attempt
                                break
                        if handoff_pick:
                            break
                    if handoff_pick:
                        break

                handoff_round_result: dict[str, Any] = {
                    "round": handoff_round,
                    "client_token_masked": _mask_secret(handoff_client_token, 8, 4),
                    "session_id_masked": _mask_secret(handoff_session_id, 6, 4),
                    "runtime_plain_session": f"0x{fallback_plain_session_int:010x}",
                    "agent_http": {
                        "selected": handoff_pick,
                        "attempts": handoff_attempts,
                    },
                }
                handoff_stream_type = str((integrated_plain_handoff or {}).get("stream_type") or "Extra1")
                handoff_parsed = handoff_pick.get("parsed") if isinstance(handoff_pick.get("parsed"), dict) else {}
                if handoff_parsed.get("agent_server_ip") and handoff_parsed.get("agent_server_port"):
                    handoff_server = {
                        "ip": handoff_parsed.get("agent_server_ip"),
                        "port": int(handoff_parsed.get("agent_server_port") or 0),
                        "random_str": handoff_parsed.get("random_str"),
                        "protocol_mode": handoff_parsed.get("protocol_mode"),
                    }
                    handoff_round_result["agent_server"] = handoff_server
                    handoff_result = run_local_agent_live_probe(
                        upstream_host=str(handoff_parsed.get("agent_server_ip")),
                        upstream_port=int(handoff_parsed.get("agent_server_port") or 0),
                        authcode=authcode,
                        client_token=handoff_client_token,
                        serial=serial_number,
                        session=handoff_session_id,
                        session_int=fallback_plain_session_int,
                        channel=channel,
                        stream_type=handoff_stream_type,
                        trans_mode="TCP",
                        combine_mode="NONE",
                        msg_id=0x18,
                        code=0x00008505,
                        code_endian="be",
                        timeout=handoff_probe_timeout,
                        capture_seconds=capture_seconds,
                        max_frames=max_frames,
                        random_str=str(handoff_parsed.get("random_str") or ""),
                        media_random_str=str(result.get("media_random_str") or ""),
                        vekey1=str(result.get("vekey1") or ""),
                        followup_frames=build_plain_claim_replay_followups(
                                session_int=fallback_plain_session_int,
                                channel=channel,
                                stream_type=handoff_stream_type,
                                trans_mode="TCP",
                                combine_mode="NONE",
                                msg_id=0x18,
                                code=0x00008505,
                                replay_count=plain_claim_replay_count_default,
                            ),
                        on_data_frame_payload=_forward_plain_handoff_payload,
                        stop_event=stop_event,
                        extend_on_activity=plain_handoff_extend_on_activity,
                        )
                    handoff_round_result["agent_bind"] = handoff_result.get("agent_bind") or {}
                    handoff_result["controller_summary"] = analyze_live_controller_flow(handoff_result)
                    handoff_result["local_bootstrap_summary"] = _ensure_local_bootstrap_summary(
                        handoff_result,
                        controller_status=str((handoff_result.get("controller_summary") or {}).get("status") or ""),
                        media_random_str=str(handoff_result.get("media_random_str") or ""),
                        vekey1=str(handoff_result.get("vekey1") or ""),
                    )
                    handoff_round_result["probe"] = handoff_result
                    data_count = int((((handoff_result.get("frames") or {}).get("data")) or 0))
                    handshake_ok = bool(((handoff_result.get("handshake") or {}).get("ok")))
                    control_count = int((((handoff_result.get("frames") or {}).get("control")) or 0))
                    score = (1000 if data_count > 0 else 0) + (100 if control_count > 0 else 0) + (10 if handshake_ok else 0)
                    if score > best_handoff_score:
                        best_handoff_score = score
                        best_handoff_attempt = {
                            "selected": handoff_pick,
                            "attempts": handoff_attempts,
                            "client_token_masked": _mask_secret(handoff_client_token, 8, 4),
                            "session_id_masked": _mask_secret(handoff_session_id, 6, 4),
                        }
                        best_handoff_server = dict(handoff_server)
                        best_handoff_probe = handoff_result
                    if data_count > 0 or str(handoff_result.get("status") or "") == "ok":
                        result["plain_handoff_runs"].append(handoff_round_result)
                        break
                result["plain_handoff_runs"].append(handoff_round_result)

            result["plain_handoff_agent_http"] = best_handoff_attempt
            result["plain_handoff_agent_server"] = best_handoff_server
            result["tcp_plain_handoff_probe"] = best_handoff_probe
            if best_handoff_probe:
                probe_statuses.append(str(best_handoff_probe.get("status") or ""))

        handoff_probe = result.get("tcp_plain_handoff_probe") if isinstance(result.get("tcp_plain_handoff_probe"), dict) else {}
        handoff_opmonitor = (handoff_probe.get("opmonitor") or {}) if isinstance(handoff_probe, dict) else {}
        handoff_response = handoff_opmonitor.get("response") if isinstance(handoff_opmonitor.get("response"), dict) else {}
        handoff_ret = _intish(handoff_response.get("Ret"), -1)
        handoff_data_count = _intish((((handoff_probe.get("frames") or {}).get("data"))), 0)
        gwm_token = str((encrypted_login_followup or {}).get("token_username") or "").strip()
        gwm_admin_token = str((encrypted_login_followup or {}).get("admin_token") or "").strip()
        if not gwm_token and gwm_admin_token:
            gwm_token = derive_futurehome_token_username(serial_number, gwm_admin_token)
        gwm_username = str((encrypted_login_followup or {}).get("username") or "").strip()
        gwm_password = str((encrypted_login_followup or {}).get("password") or "")
        if (
            plain_handoff
            and (gwm_ams_url or server_ip or server_port)
            and handoff_data_count < 1
            and handoff_ret == 103
            and gwm_token
        ):
            try:
                gwm_probe = run_gwm_live_probe(
                    ams_url=gwm_ams_url,
                    server_host=server_ip,
                    server_port=_intish(server_port, 0),
                    serial_number=serial_number,
                    authcode=authcode,
                    channel=channel,
                    stream_type=stream_type,
                    token_username=gwm_token,
                    username=gwm_username,
                    password=gwm_password,
                    uuid_text=developer_id or "xmeye",
                    app_key=app_key,
                    vendor_name=vendor,
                    timeout=min(float(timeout), 12.0),
                    capture_seconds=max(6.0, float(capture_seconds)),
                    max_frames=max_frames,
                    user_agent=self.status_user_agent,
                    ssl_verify=self.agent_ssl_verify,
                )
            except Exception as exc:  # noqa: BLE001
                gwm_probe = {
                    "status": "error",
                    "error": f"gwm_probe_failed: {exc}",
                }
            result["gwm_probe"] = gwm_probe
            if int((((gwm_probe.get("frames") or {}).get("data")) or 0)) > 0 or str(gwm_probe.get("status") or "") == "ok":
                probe_statuses.append("ok")
            elif gwm_probe:
                probe_statuses.append(str(gwm_probe.get("status") or ""))

        gwm_probe = result.get("gwm_probe") if isinstance(result.get("gwm_probe"), dict) else {}
        gwm_status = str(gwm_probe.get("status") or "")
        gwm_data_count = _intish((((gwm_probe.get("frames") or {}).get("data"))), 0)
        wakeup_should_run = (
            plain_handoff
            and wakeup_probe_enabled
            and (device_idr_auto_wakeup or bool(str(wakeup_host or "").strip()) or int(wakeup_port or 0) > 0)
            and handoff_data_count < 1
            and handoff_ret == 103
            and gwm_status in {"", "error", "partial"}
            and gwm_data_count < 1
        )
        if wakeup_should_run:
            idr_probe = result.get("idr_status_probe") if isinstance(result.get("idr_status_probe"), dict) else {}
            if not idr_probe:
                idr_probe = run_idr_status_probe(
                    serial_number=serial_number,
                    authcode=authcode,
                    manufacturer_candidates=[
                        device_oem_id,
                        device_hardware,
                        vendor,
                    ],
                    timeout=min(timeout, 12),
                    user_agent=self.status_user_agent,
                    ssl_verify=self.agent_ssl_verify,
                    content_types=[self.status_content_type],
                )
            result["idr_status_probe"] = idr_probe
            try:
                wakeup_probe = run_wakeup_cycle_probe(
                    serial_number=serial_number,
                    authcode=authcode,
                    idr_probe=idr_probe,
                    manufacturer_candidates=[
                        device_oem_id,
                        device_hardware,
                        vendor,
                    ],
                    wakeup_host=str(wakeup_host or "").strip(),
                    wakeup_port=int(wakeup_port or 0),
                    timeout=min(float(timeout), 12.0),
                    user_agent=self.status_user_agent,
                    ssl_verify=self.agent_ssl_verify,
                    content_types=[self.status_content_type],
                )
            except Exception as exc:  # noqa: BLE001
                wakeup_probe = {
                    "status": "error",
                    "error": f"wakeup_probe_failed: {exc}",
                }
            result["wakeup_probe"] = wakeup_probe
            selected_wakeup = (wakeup_probe.get("selected") or wakeup_probe) if isinstance(wakeup_probe, dict) else {}
            wake_response = (selected_wakeup.get("response") or {}) if isinstance(selected_wakeup, dict) else {}
            wake_server_ip = str(wake_response.get("server_ip") or "").strip()
            wake_server_port = _intish(wake_response.get("server_port"), 0)
            if wake_server_ip and wake_server_port > 0 and gwm_token:
                try:
                    gwm_after_wakeup = run_gwm_live_probe(
                        ams_url=gwm_ams_url,
                        server_host=wake_server_ip,
                        server_port=wake_server_port,
                        serial_number=serial_number,
                        authcode=authcode,
                        channel=channel,
                        stream_type=stream_type,
                        token_username=gwm_token,
                        username=gwm_username,
                        password=gwm_password,
                        uuid_text=developer_id or "xmeye",
                        app_key=app_key,
                        vendor_name=vendor,
                        timeout=min(float(timeout), 12.0),
                        capture_seconds=max(6.0, float(capture_seconds)),
                        max_frames=max_frames,
                        user_agent=self.status_user_agent,
                        ssl_verify=self.agent_ssl_verify,
                    )
                except Exception as exc:  # noqa: BLE001
                    gwm_after_wakeup = {
                        "status": "error",
                        "error": f"gwm_probe_after_wakeup_failed: {exc}",
                    }
                result["gwm_probe_after_wakeup"] = gwm_after_wakeup
                if int((((gwm_after_wakeup.get("frames") or {}).get("data")) or 0)) > 0 or str(gwm_after_wakeup.get("status") or "") == "ok":
                    probe_statuses.append("ok")
                elif gwm_after_wakeup:
                    probe_statuses.append(str(gwm_after_wakeup.get("status") or ""))

        if "ok" in probe_statuses:
            result["status"] = "ok"
        elif "partial" in probe_statuses:
            result["status"] = "partial"
        return result


class BossApi:
    def __init__(self, base_urls: list[str] | None = None) -> None:
        self.base_urls = base_urls or list(DEFAULT_BOSS_BASES)

    @staticmethod
    def guess_login_payloads(account: str, password: str, app_key: str = "", iso_code: str = "") -> list[dict[str, Any]]:
        base_candidates = [
            {"account": account, "password": password},
            {"username": account, "password": password},
            {"userName": account, "password": password},
            {"email": account, "password": password},
            {"account": account, "passwd": password},
            {"account": account, "pwd": password},
            {"loginName": account, "password": password},
            {"accountName": account, "password": password},
        ]
        output: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in base_candidates:
            if app_key:
                item = dict(item, appKey=app_key)
            if iso_code:
                item = dict(item, isoCode=iso_code, countryCode=iso_code)
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            output.append(item)
        return output

    def experimental_login(self, payloads: list[dict[str, Any]], timeout: int = 20) -> list[HttpResult]:
        results: list[HttpResult] = []
        for base in self.base_urls:
            url = f"{base}{LOGIN_PATH}"
            for payload in payloads:
                # H5 myRequest(type=1) wraps payload as {"request": payload}.
                wrapped = {"request": payload}
                results.append(http_json(url=url, method="POST", payload=wrapped, timeout=timeout))
                # Add direct form as fallback.
                results.append(http_json(url=url, method="POST", payload=payload, timeout=timeout))
        return results


@dataclass
class OpenApiCreds:
    uuid: str
    app_key: str
    move_card: int
    secret: str
    bases: list[str] | None = None
    dev_muserid: str = ""

    def signed_headers(self) -> dict[str, str]:
        return build_signed_headers(
            SignedHeadersInput(
                uuid=self.uuid,
                app_key=self.app_key,
                move_card=self.move_card,
                secret=self.secret,
            )
        )

    @property
    def base_urls(self) -> list[str]:
        return self.bases or list(DEFAULT_OPENAPI_BASES)


class OpenApiProbe:
    def __init__(self, creds: OpenApiCreds) -> None:
        self.creds = creds

    def _call(
        self,
        path: str,
        payload: dict[str, Any],
        timeout: int = 20,
        extra_headers: dict[str, str] | None = None,
    ) -> list[HttpResult]:
        results: list[HttpResult] = []
        headers = self.creds.signed_headers()
        if extra_headers:
            headers.update(extra_headers)
        body = dict(payload)
        if self.creds.dev_muserid and "muserid" not in body:
            body["muserid"] = self.creds.dev_muserid
        for base in self.creds.base_urls:
            url = urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            results.append(http_json(url=url, method="POST", payload=body, headers=headers, timeout=timeout))
        return results

    def probe_v3_rtc_device_token(self, device_id: str, channel: int | None = None, timeout: int = 20) -> list[HttpResult]:
        resolved_channel = channel if channel is not None else 0
        payloads = [
            {"sns": [device_id]},
            {"sns": [device_id], "channel": resolved_channel},
            {"sns": device_id},
            {"sns": device_id, "channel": resolved_channel},
            {"sn": device_id},
            {"deviceId": device_id},
            {"devId": device_id},
            {"sn": device_id, "channel": resolved_channel},
            {"deviceId": device_id, "channel": resolved_channel},
        ]
        out: list[HttpResult] = []
        for payload in payloads:
            out.extend(self._call("/gwp/v3/rtc/device/token", payload, timeout=timeout))
        return out

    @staticmethod
    def _extract_rtc_tokens(token_results: list[HttpResult]) -> list[str]:
        tokens: list[str] = []
        for result in token_results:
            source = result.json_data if result.json_data is not None else result.text
            hints = _extract_auth_hints(source)
            tokens.extend(hints.device_tokens)
            tokens.extend(hints.user_tokens)
            if isinstance(result.json_data, dict):
                data = result.json_data.get("data")
                rows: list[dict[str, Any]] = []
                if isinstance(data, list):
                    rows = [item for item in data if isinstance(item, dict)]
                elif isinstance(data, dict):
                    rows = [data]
                for row in rows:
                    for key in ("token", "deviceToken", "loginToken", "accessToken"):
                        value = row.get(key)
                        if isinstance(value, str) and _looks_like_token(value):
                            tokens.append(value.strip())
        return _dedupe(tokens)

    def probe_device_login_with_rtc_tokens(
        self,
        device_id: str,
        rtc_tokens: list[str],
        channel: int | None = None,
        timeout: int = 20,
    ) -> list[HttpResult]:
        if not rtc_tokens:
            return []
        resolved_channel = channel if channel is not None else 0
        out: list[HttpResult] = []
        for token in rtc_tokens[:3]:
            token = token.strip()
            if not token:
                continue
            paths = [f"/gwp/v3/rtc/device/login/{token}"]
            payloads = [
                {"loginToken": token},
                {"loginToken": token, "channel": resolved_channel},
                {"token": token},
                {"token": token, "channel": resolved_channel},
                {"loginToken": token, "sn": device_id},
            ]
            for path in paths:
                for payload in payloads:
                    out.extend(self._call(path, payload, timeout=timeout))
        return out

    @staticmethod
    def _extract_login_contexts(login_results: list[HttpResult], device_id: str) -> list[dict[str, str]]:
        contexts: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for result in login_results:
            if not _is_success(result):
                continue
            session_id = ""
            if isinstance(result.json_data, dict) and isinstance(result.json_data.get("data"), dict):
                raw_session = result.json_data["data"].get("SessionID")
                if isinstance(raw_session, str):
                    session_id = raw_session.strip()
            if not session_id:
                continue

            token = ""
            payload = result.request_payload if isinstance(result.request_payload, dict) else {}
            for key in ("loginToken", "token", "deviceToken", "accessToken"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    token = value.strip()
                    break
            if not token:
                marker = "/gwp/v3/rtc/device/login/"
                idx = result.url.find(marker)
                if idx >= 0:
                    tail = result.url[idx + len(marker) :]
                    token_candidate = tail.split("/", 1)[0].strip()
                    if token_candidate and token_candidate != device_id:
                        token = token_candidate
            if not token:
                continue
            pair = (token, session_id)
            if pair in seen:
                continue
            seen.add(pair)
            contexts.append(
                {
                    "token": token,
                    "session_id": session_id,
                    "url": result.url,
                }
            )
        return contexts

    def probe_volet_paths(
        self,
        device_id: str,
        rtc_tokens: list[str],
        session_ids: list[str],
        channel: int | None = None,
        timeout: int = 20,
    ) -> list[HttpResult]:
        if not rtc_tokens:
            return []
        resolved_channel = channel if channel is not None else 0
        out: list[HttpResult] = []
        targets = _dedupe([sid.strip() for sid in session_ids if sid.strip()] + [device_id, str(resolved_channel)])
        for token in rtc_tokens[:3]:
            token = token.strip()
            if not token:
                continue
            prefixes = [
                f"login/{token}",
                f"login/{token}/",
                token,
                f"{token}/",
            ]
            operations = ("GetInfo", "Query")
            payloads = [
                {},
                {"sn": device_id},
                {"sns": [device_id]},
                {"channel": resolved_channel},
            ]
            for session_id in session_ids[:2]:
                if session_id:
                    payloads.append({"SessionID": session_id, "channel": resolved_channel})
            for prefix in prefixes:
                for op in operations:
                    for target in targets:
                        path = f"/gwp/v3/rtc/device/{prefix}{op}/{target}"
                        for payload in payloads:
                            out.extend(self._call(path, payload, timeout=timeout))
        return out

    def probe_device_runtime_paths(
        self,
        device_id: str,
        rtc_tokens: list[str],
        session_ids: list[str],
        channel: int | None = None,
        timeout: int = 20,
    ) -> list[HttpResult]:
        resolved_channel = channel if channel is not None else 0
        identities = _dedupe([device_id] + [tok.strip() for tok in rtc_tokens[:2] if tok.strip()] + [sid.strip() for sid in session_ids[:1] if sid.strip()])
        if not identities:
            return []
        config_identities = _dedupe([tok.strip() for tok in rtc_tokens[:2] if tok.strip()]) or identities

        out: list[HttpResult] = []
        for ident in identities:
            base_payloads: list[dict[str, Any]] = [
                {"sn": device_id, "channel": resolved_channel},
                {"channel": resolved_channel},
            ]
            for session_id in session_ids[:2]:
                if session_id:
                    base_payloads.append({"SessionID": session_id, "channel": resolved_channel})
                    base_payloads.append({"SessionID": session_id, "sn": device_id, "channel": resolved_channel})
            for payload in base_payloads:
                out.extend(self._call(f"/gwp/v3/rtc/device/getAlarmCount/{ident}", payload, timeout=timeout))
                out.extend(self._call(f"/gwp/v3/rtc/device/getDeviceAlarmList/{ident}", payload, timeout=timeout))
                out.extend(self._call(f"/gwp/v3/rtc/device/audioGetAlarmTypeInfo/{ident}", payload, timeout=timeout))

            config_names = [
                "SystemInfo",
                "SystemFunction",
                "NetWork.NetPubCfgDomain",
                "NetWork.NetCommon",
                "NetWork.RTSP",
                "NetWork.NetRTSP",
                "NetWork.NetNat",
                "NetWork.NetServer",
                "NetWork.Onvif",
                "NetWork.NetPMS",
                "NetWork.NetPMSV2",
                "Simplify.Encode",
                "Camera.Param",
                "Storage",
                "Record",
                "General.General",
                "ChannelTitle",
            ]
            config_payloads: list[dict[str, Any]] = []
            for name in config_names:
                config_payloads.append({"Name": name})
                for session_id in session_ids[:2]:
                    if session_id:
                        config_payloads.append({"Name": name, "SessionID": session_id})
            for payload in config_payloads:
                for config_ident in config_identities:
                    out.extend(self._call(f"/gwp/v3/rtc/device/getconfig/{config_ident}", payload, timeout=timeout))
        return out

    def probe_device_login(
        self,
        device_id: str,
        device_user: str = "",
        device_pass: str = "",
        channel: int | None = None,
        timeout: int = 20,
    ) -> list[HttpResult]:
        payloads = [
            {},
            {"channel": channel if channel is not None else 0},
            {"userName": device_user, "password": device_pass},
            {"username": device_user, "password": device_pass},
            {"account": device_user, "password": device_pass},
            {"loginName": device_user, "password": device_pass},
            {"userName": device_user, "password": device_pass, "channel": channel if channel is not None else 0},
        ]
        out: list[HttpResult] = []
        path = f"/gwp/v3/rtc/device/login/{device_id}"
        for payload in payloads:
            cleaned = {k: v for k, v in payload.items() if v not in ("", None)}
            out.extend(self._call(path, cleaned, timeout=timeout))
        return out

    def probe_get_info(self, device_id: str, timeout: int = 20) -> list[HttpResult]:
        payloads = [
            {},
            {"sn": device_id},
            {"deviceId": device_id},
        ]
        out: list[HttpResult] = []
        paths = [
            f"/gwp/v3/rtc/device/v1/call/getInfo/{device_id}",
            f"/gwp/v3/rtc/device/v1/call/GetInfo/{device_id}",
        ]
        for path in paths:
            for payload in payloads:
                out.extend(self._call(path, payload, timeout=timeout))
        return out

    def run_live_probe(
        self,
        device_id: str,
        device_user: str = "",
        device_pass: str = "",
        channel: int | None = None,
        timeout: int = 20,
    ) -> dict[str, Any]:
        token_results = self.probe_v3_rtc_device_token(device_id=device_id, channel=channel, timeout=timeout)
        rtc_tokens = self._extract_rtc_tokens(token_results)
        login_token_results = self.probe_device_login_with_rtc_tokens(
            device_id=device_id,
            rtc_tokens=rtc_tokens,
            channel=channel,
            timeout=timeout,
        )
        login_contexts = self._extract_login_contexts(login_token_results, device_id=device_id)
        session_ids = _dedupe([ctx.get("session_id", "").strip() for ctx in login_contexts if ctx.get("session_id")])
        login_results = self.probe_device_login(
            device_id=device_id,
            device_user=device_user,
            device_pass=device_pass,
            channel=channel,
            timeout=timeout,
        )
        info_results = self.probe_get_info(device_id=device_id, timeout=timeout)
        volet_results = self.probe_volet_paths(
            device_id=device_id,
            rtc_tokens=rtc_tokens,
            session_ids=session_ids,
            channel=channel,
            timeout=timeout,
        )
        runtime_results = self.probe_device_runtime_paths(
            device_id=device_id,
            rtc_tokens=rtc_tokens,
            session_ids=session_ids,
            channel=channel,
            timeout=timeout,
        )
        stream_urls: set[str] = set()
        for result in token_results + login_token_results + login_results + info_results + volet_results + runtime_results:
            stream_urls.update(extract_possible_stream_urls(result.json_data or result.text))
        runtime_dicts = [r.__dict__ for r in runtime_results]
        return {
            "rtc_tokens_masked": [_mask_secret(value, 8, 4) for value in rtc_tokens],
            "login_contexts": [
                {
                    "token_masked": _mask_secret(str(item.get("token") or ""), 8, 4),
                    "session_id": str(item.get("session_id") or ""),
                    "source_url": str(item.get("url") or ""),
                }
                for item in login_contexts
            ],
            "token_results": [r.__dict__ for r in token_results],
            "login_token_results": [r.__dict__ for r in login_token_results],
            "login_results": [r.__dict__ for r in login_results],
            "info_results": [r.__dict__ for r in info_results],
            "volet_results": [r.__dict__ for r in volet_results],
            "runtime_results": runtime_dicts,
            "possible_stream_urls": sorted(stream_urls),
            "config_summary": _extract_live_config_summary({"runtime_results": runtime_dicts}),
        }


def build_h5_cloud_url(
    access_token: str,
    app_key: str,
    lang: str = "ru",
    app_scheme: str = "icsee.boss.jftech.com",
    app_ver: str = "7.7.7",
    base: str = "https://boss-api-as.jftechsoft.com/index",
) -> str:
    query = urllib.parse.urlencode(
        {
            "appKey": app_key,
            "authorization": access_token,
            "lang": lang,
            "appScheme": app_scheme,
            "appVer": app_ver,
        }
    )
    return f"{base}?{query}"


@dataclass
class CloudAuthSession:
    account: str
    user_token: str
    refresh_token: str = ""
    token_expires_utc: str = ""
    app_key: str = ""
    vendor: str = ""
    uuid: str = ""
    move_card: int = 0
    secret: str = ""
    device_token: str = ""
    dev_muserid: str = ""
    public_key: str = ""
    vms_key: str = ""
    boss_base: str = ""
    raw_login: dict[str, Any] = field(default_factory=dict)
    raw_device_token: dict[str, Any] = field(default_factory=dict)
    raw_ams_device_list: dict[str, Any] = field(default_factory=dict)
    raw_acapp_auth_list: dict[str, Any] = field(default_factory=dict)


@dataclass
class LiveDescriptor:
    endpoint: str
    payload: dict[str, Any]
    result: HttpResult
    urls: list[str]


@dataclass
class PlayableUrlResult:
    url: str
    scheme: str
    headers: dict[str, str]
    source_endpoint: str
    confidence: float
    status: str = "ok"
    note: str = ""


@dataclass
class _AuthHints:
    user_tokens: list[str] = field(default_factory=list)
    device_tokens: list[str] = field(default_factory=list)
    app_keys: list[str] = field(default_factory=list)
    vendors: list[str] = field(default_factory=list)
    uuids: list[str] = field(default_factory=list)
    move_cards: list[int] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    public_keys: list[str] = field(default_factory=list)
    vms_keys: list[str] = field(default_factory=list)
    muserids: list[str] = field(default_factory=list)
    device_ids: list[str] = field(default_factory=list)


SUCCESS_CODES = {"0", "200", "2000", "success", "ok"}
TOKEN_ERROR_CODES = {"-91002", "-91003", "-91004", "4002", "4003", "4004", "401", "4010"}


def _mask_secret(value: str, keep_head: int = 8, keep_tail: int = 4) -> str:
    if not value:
        return value
    if len(value) <= keep_head + keep_tail:
        return "*" * len(value)
    return f"{value[:keep_head]}...{value[-keep_tail:]}"


def _normalize_sensitive_values(values: Iterable[str]) -> list[str]:
    prepared: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        token = value.strip()
        if not token:
            continue
        token_l = token.lower()
        if token_l.startswith("bearer "):
            token = token[7:].strip()
        # Ignore tiny fragments to avoid over-masking regular text.
        if len(token) < 16:
            continue
        prepared.append(token)
    prepared = _dedupe(prepared)
    prepared.sort(key=len, reverse=True)
    return prepared


def _mask_secrets_in_text(text: str, secrets: list[str]) -> str:
    if not isinstance(text, str) or not text or not secrets:
        return text
    out = text
    for secret in secrets:
        if secret in out:
            out = out.replace(secret, _mask_secret(secret, 8, 4))
    return out


def _mask_secrets_in_obj(obj: Any, secrets: list[str]) -> Any:
    if not secrets:
        return obj
    if isinstance(obj, str):
        return _mask_secrets_in_text(obj, secrets)
    if isinstance(obj, dict):
        return {key: _mask_secrets_in_obj(value, secrets) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_mask_secrets_in_obj(item, secrets) for item in obj]
    return obj


def _extract_probe_sensitive_values(probe_result: dict[str, Any]) -> list[str]:
    sensitive: list[str] = []
    for group, rows in probe_result.items():
        if not str(group).endswith("_results") or not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            source = row.get("json_data")
            if source is None:
                source = row.get("text")
            hints = _extract_auth_hints(source)
            sensitive.extend(hints.user_tokens)
            sensitive.extend(hints.device_tokens)
            payload = row.get("request_payload")
            if isinstance(payload, dict):
                for key in ("token", "loginToken", "deviceToken", "accessToken", "authorization"):
                    value = payload.get(key)
                    if isinstance(value, str):
                        sensitive.append(value)
            url = row.get("url")
            if isinstance(url, str) and "/gwp/v3/rtc/device/login/" in url:
                tail = url.split("/gwp/v3/rtc/device/login/", 1)[1]
                token_candidate = tail.split("/", 1)[0]
                sensitive.append(token_candidate)
    return _normalize_sensitive_values(sensitive)


def _sanitize_live_probe(probe_result: dict[str, Any]) -> dict[str, Any]:
    secrets = _extract_probe_sensitive_values(probe_result)
    sanitized: dict[str, Any] = {}
    for key, value in probe_result.items():
        if str(key).endswith("_results"):
            sanitized[key] = _mask_secrets_in_obj(value, secrets)
        elif key == "possible_stream_urls" and isinstance(value, list):
            sanitized[key] = [_mask_secrets_in_text(str(item), secrets) for item in value]
        else:
            sanitized[key] = _mask_secrets_in_obj(value, secrets)
    return sanitized


def _decode_ipv4_hex(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw.lower().startswith("0x"):
        return ""
    try:
        num = int(raw, 16)
    except Exception:
        return ""
    if num < 0 or num > 0xFFFFFFFF:
        return ""
    little = ".".join(str(part) for part in num.to_bytes(4, "little"))
    big = ".".join(str(part) for part in num.to_bytes(4, "big"))
    if little.startswith(("10.", "172.", "192.168.", "169.254.")):
        return little
    return big


def _extract_live_config_summary(probe_result: dict[str, Any]) -> dict[str, Any]:
    runtime_rows = probe_result.get("runtime_results")
    if not isinstance(runtime_rows, list):
        return {}

    by_name: dict[str, dict[str, Any]] = {}
    failures: list[dict[str, Any]] = []
    session_ids: list[str] = []
    for row in runtime_rows:
        if not isinstance(row, dict):
            continue
        payload = row.get("request_payload")
        if not isinstance(payload, dict):
            payload = {}
        json_data = row.get("json_data")
        if not isinstance(json_data, dict) or str(json_data.get("code")) != "2000":
            continue
        data = json_data.get("data")
        if not isinstance(data, dict):
            continue
        name = str(data.get("Name") or payload.get("Name") or "").strip()
        if not name:
            continue
        if name not in by_name:
            by_name[name] = data
        session_id = str(data.get("SessionID") or "").strip()
        if session_id:
            session_ids.append(session_id)
        ret = data.get("Ret")
        if ret not in (None, 100):
            failures.append(
                {
                    "name": name,
                    "ret": ret,
                    "ret_msg": str(data.get("RetMsg") or ""),
                }
            )

    if not by_name:
        return {}

    summary: dict[str, Any] = {
        "session_id": _dedupe([sid for sid in session_ids if sid])[:1][0] if session_ids else "",
        "available_configs": sorted(by_name),
    }
    if failures:
        summary["parse_failures"] = failures

    pub_cfg = by_name.get("NetWork.NetPubCfgDomain")
    if isinstance(pub_cfg, dict):
        info = pub_cfg.get("NetWork.NetPubCfgDomain")
        if isinstance(info, dict):
            summary["pub_tcs"] = {
                "cfg_host": str(info.get("NetPub-Cfg") or ""),
                "dns1": str(info.get("NetPub-DNS1") or ""),
                "url": str(info.get("NetPub-Tcs") or ""),
            }

    net_common = by_name.get("NetWork.NetCommon")
    if isinstance(net_common, dict):
        info = net_common.get("NetWork.NetCommon")
        if isinstance(info, dict):
            summary["network"] = {
                "host_name": str(info.get("HostName") or ""),
                "host_ip_raw": str(info.get("HostIP") or ""),
                "host_ip": _decode_ipv4_hex(info.get("HostIP")),
                "gateway_raw": str(info.get("GateWay") or ""),
                "gateway": _decode_ipv4_hex(info.get("GateWay")),
                "http_port": info.get("HttpPort"),
                "ssl_port": info.get("SSLPort"),
                "tcp_port": info.get("TCPPort"),
                "udp_port": info.get("UDPPort"),
                "mon_mode": str(info.get("MonMode") or ""),
                "transfer_plan": str(info.get("TransferPlan") or ""),
                "use_hs_download": bool(info.get("UseHSDownLoad")) if "UseHSDownLoad" in info else None,
            }

    rtsp_cfg = by_name.get("NetWork.RTSP")
    if isinstance(rtsp_cfg, dict):
        info = rtsp_cfg.get("NetWork.RTSP")
        if isinstance(info, dict):
            server = info.get("Server") if isinstance(info.get("Server"), dict) else {}
            client = info.get("Client") if isinstance(info.get("Client"), dict) else {}
            host_hint = ""
            network = summary.get("network")
            if isinstance(network, dict):
                host_hint = str(network.get("host_ip") or "")
            summary["rtsp"] = {
                "is_server": bool(info.get("IsServer")),
                "is_client": bool(info.get("IsClient")),
                "port": server.get("Port"),
                "auth_type": str(server.get("AuthType") or ""),
                "server_address_raw": str(server.get("Address") or ""),
                "server_address_hint": host_hint,
                "client_port": client.get("Port"),
            }

    encode_cfg = by_name.get("Simplify.Encode")
    if isinstance(encode_cfg, dict):
        rows = encode_cfg.get("Simplify.Encode")
        first = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else {}
        main_fmt = first.get("MainFormat") if isinstance(first.get("MainFormat"), dict) else {}
        extra_fmt = first.get("ExtraFormat") if isinstance(first.get("ExtraFormat"), dict) else {}
        main_video = main_fmt.get("Video") if isinstance(main_fmt.get("Video"), dict) else {}
        extra_video = extra_fmt.get("Video") if isinstance(extra_fmt.get("Video"), dict) else {}
        summary["encode"] = {
            "main": {
                "compression": str(main_video.get("Compression") or ""),
                "resolution": str(main_video.get("Resolution") or ""),
                "fps": main_video.get("FPS"),
                "bitrate": main_video.get("BitRate"),
                "bitrate_control": str(main_video.get("BitRateControl") or ""),
            },
            "extra": {
                "compression": str(extra_video.get("Compression") or ""),
                "resolution": str(extra_video.get("Resolution") or ""),
                "fps": extra_video.get("FPS"),
                "bitrate": extra_video.get("BitRate"),
                "bitrate_control": str(extra_video.get("BitRateControl") or ""),
            },
        }

    storage_cfg = by_name.get("Storage")
    if isinstance(storage_cfg, dict):
        info = storage_cfg.get("Storage")
        if isinstance(info, dict):
            summary["storage"] = {
                "record_stream": info.get("RecordStream"),
                "sd_status": info.get("SDCheckStatus"),
            }

    titles = by_name.get("ChannelTitle")
    if isinstance(titles, dict) and isinstance(titles.get("ChannelTitle"), list):
        summary["channel_titles"] = [str(item) for item in titles.get("ChannelTitle") if isinstance(item, str)]

    return summary


def _dedupe(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _walk_pairs(obj: Any, parent: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_s = str(key)
            full = f"{parent}.{key_s}" if parent else key_s
            yield full, value
            yield from _walk_pairs(value, full)
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            full = f"{parent}[{idx}]"
            yield full, value
            yield from _walk_pairs(value, full)


def _extract_code_and_msg(payload: Any) -> tuple[str, str]:
    if not isinstance(payload, dict):
        return "", ""
    code = payload.get("code")
    msg = payload.get("msg") or payload.get("message") or payload.get("error") or payload.get("errorMsg") or ""
    return ("" if code is None else str(code).strip()), str(msg).strip()


def _looks_like_token(value: str) -> bool:
    raw = value.strip()
    if not raw:
        return False
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    if len(raw) < 24:
        return False
    if any(ch.isspace() for ch in raw):
        return False
    return True


def _looks_like_device_id(value: str) -> bool:
    raw = value.strip()
    if not raw or len(raw) < 6 or len(raw) > 64:
        return False
    return raw.replace("-", "").replace("_", "").isalnum()


def _pick_best_token(values: list[str]) -> str:
    if not values:
        return ""
    unique = _dedupe(v.strip() for v in values if v and v.strip())

    def score(token: str) -> tuple[int, int]:
        stripped = token[7:].strip() if token.lower().startswith("bearer ") else token
        return (1 if stripped.count(".") == 2 else 0, len(stripped))

    unique.sort(key=score, reverse=True)
    return unique[0]


def _extract_admin_token_from_payload(payload: Any) -> str:
    hints = _extract_auth_hints(payload)
    token = _pick_best_token(hints.device_tokens)
    if token:
        return token
    if not isinstance(payload, dict):
        return ""
    containers: list[dict[str, Any]] = [payload]
    data = payload.get("data")
    if isinstance(data, dict):
        containers.append(data)
    for item in containers:
        for key in ("adminToken", "AdminToken", "deviceToken", "loginToken", "token"):
            value = item.get(key)
            if isinstance(value, str) and _looks_like_token(value):
                return value.strip()
        nested = item.get("deviceToken")
        if isinstance(nested, dict):
            for key in ("adminToken", "AdminToken", "token"):
                value = nested.get(key)
                if isinstance(value, str) and _looks_like_token(value):
                    return value.strip()
    return ""


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    raw = token.strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    parts = raw.split(".")
    if len(parts) < 2:
        return {}
    pad = "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode((parts[1] + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _jwt_expiry_utc(token: str) -> str:
    payload = _decode_jwt_payload(token)
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return ""
    return datetime.utcfromtimestamp(exp).strftime("%Y-%m-%d %H:%M:%S UTC")


def _extract_auth_hints(payload: Any) -> _AuthHints:
    hints = _AuthHints()
    for full_key, value in _walk_pairs(payload):
        key = full_key.rsplit(".", 1)[-1]
        key = key.split("[", 1)[0].strip().lower()
        if isinstance(value, str):
            text = value.strip()
            if not text:
                continue
            if key in {"token", "accesstoken", "usertoken", "authorization", "authtoken", "vmsatoken"}:
                if _looks_like_token(text):
                    hints.user_tokens.append(text)
            elif key.endswith("token") and any(mark in key for mark in ("device", "share", "admin", "login")):
                if _looks_like_token(text):
                    hints.device_tokens.append(text)
            elif key.endswith("token") and _looks_like_token(text):
                hints.user_tokens.append(text)

            if key in {"appkey", "vmsappkey"}:
                hints.app_keys.append(text)
            elif key in {"vendor", "vendorname"}:
                hints.vendors.append(text)
            elif key in {"uuid", "appuser"}:
                hints.uuids.append(text)
            elif key == "secret":
                hints.secrets.append(text)
            elif key == "movecard":
                try:
                    hints.move_cards.append(int(text))
                except Exception:
                    pass
            elif key in {"vmspublickkey", "publickey"}:
                hints.public_keys.append(text)
            elif key == "vmskey":
                hints.vms_keys.append(text)
            elif "muserid" in key:
                hints.muserids.append(text)
            elif key in {"devid", "deviceid", "sn", "serialno", "devsn"} and _looks_like_device_id(text):
                hints.device_ids.append(text)
        elif isinstance(value, (int, float)):
            if key == "movecard":
                hints.move_cards.append(int(value))
            elif "muserid" in key:
                hints.muserids.append(str(int(value)))

    hints.user_tokens = _dedupe(hints.user_tokens)
    hints.device_tokens = _dedupe(hints.device_tokens)
    hints.app_keys = _dedupe(hints.app_keys)
    hints.vendors = _dedupe(hints.vendors)
    hints.uuids = _dedupe(hints.uuids)
    hints.secrets = _dedupe(hints.secrets)
    hints.public_keys = _dedupe(hints.public_keys)
    hints.vms_keys = _dedupe(hints.vms_keys)
    hints.muserids = _dedupe(hints.muserids)
    hints.device_ids = _dedupe(hints.device_ids)
    return hints


def _is_token_error(result: HttpResult) -> bool:
    code, msg = _extract_code_and_msg(result.json_data)
    code_l = code.lower()
    msg_l = msg.lower()
    if code_l in TOKEN_ERROR_CODES:
        return True
    if "token" in msg_l and any(mark in msg_l for mark in ("expire", "invalid", "fail", "error")):
        return True
    if isinstance(result.text, str):
        text_l = result.text.lower()
        if "token was expected to have 3 parts" in text_l:
            return True
    return False


def _is_success(result: HttpResult) -> bool:
    code, _ = _extract_code_and_msg(result.json_data)
    if result.status is not None and not (200 <= result.status < 300):
        return False
    if not code:
        return result.ok or (result.status is not None and 200 <= result.status < 300)
    return code.lower() in SUCCESS_CODES


def _summarize_http_results(results: list[HttpResult], limit: int = 30) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for item in results[:limit]:
        code, msg = _extract_code_and_msg(item.json_data)
        summary.append(
            {
                "ok": item.ok,
                "status": item.status,
                "code": code,
                "msg": msg[:140],
                "url": item.url,
                "error": item.error,
            }
        )
    return summary


def _score_url(url: str, source_endpoint: str) -> tuple[int, str]:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    lower = url.lower()
    if scheme in {"http", "https"}:
        # Ignore generic service/config endpoints that are not media streams.
        stream_markers = (".flv", ".m3u8", "/live", "/stream", "webrtc", "realplay", "hls")
        if not any(mark in lower for mark in stream_markers):
            return 0, scheme
    if scheme in {"ws", "wss"} and not any(mark in lower for mark in ("webrtc", "live", "stream", "rtc")):
        return 0, scheme
    score = 0
    if scheme in {"rtsp", "rtsps"}:
        score += 100
    elif scheme in {"http", "https"}:
        score += 70
        if ".flv" in lower or "flv" in lower:
            score += 20
        if ".m3u8" in lower or "hls" in lower:
            score += 12
    elif scheme in {"ws", "wss"}:
        score += 35
    if "webrtc" in lower or "rtc" in lower:
        score -= 8
    if "token_results" in source_endpoint:
        score += 3
    return score, scheme


def _crypto_ready() -> bool:
    return all(mod is not None for mod in (_AES, _PKCS1_v1_5, _RSA))


def _normalize_public_key(public_key: str) -> str:
    key = public_key.strip()
    if not key:
        return ""
    if "BEGIN PUBLIC KEY" in key:
        return key
    return "-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----"


def _generate_vms_key() -> str:
    return base64.b64encode(os.urandom(16)).decode("ascii")


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > block_size:
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]


def _encrypt_aes_req(payload: dict[str, Any], vms_key: str) -> str:
    if not _crypto_ready():
        return ""
    try:
        key_bytes = base64.b64decode(vms_key)
    except Exception:
        return ""
    if len(key_bytes) not in (16, 24, 32):
        return ""
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    cipher = _AES.new(key_bytes, _AES.MODE_ECB)
    encrypted = cipher.encrypt(_pkcs7_pad(raw, 16))
    return base64.b64encode(encrypted).decode("ascii")


def _decrypt_aes_data(encrypted_b64: str, vms_key: str) -> Any | None:
    if not _crypto_ready():
        return None
    try:
        key_bytes = base64.b64decode(vms_key)
        encrypted = base64.b64decode(encrypted_b64)
    except Exception:
        return None
    if len(key_bytes) not in (16, 24, 32):
        return None
    try:
        cipher = _AES.new(key_bytes, _AES.MODE_ECB)
        raw = cipher.decrypt(encrypted)
        text = _pkcs7_unpad(raw, 16).decode("utf-8", errors="replace").strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return text
    except Exception:
        return None


def _encrypt_rsa_key(vms_key: str, public_key: str) -> str:
    if not _crypto_ready():
        return ""
    try:
        rsa = _RSA.import_key(_normalize_public_key(public_key))
        cipher = _PKCS1_v1_5.new(rsa)
        encrypted = cipher.encrypt(vms_key.encode("utf-8"))
        return base64.b64encode(encrypted).decode("ascii")
    except Exception:
        return ""


def _claim_json_dict(claim_source: Any) -> dict[str, Any]:
    if isinstance(claim_source, dict):
        inner = claim_source.get("json")
        if isinstance(inner, dict):
            return inner
        return claim_source
    return {}


def _pick_claim_str(claim: dict[str, Any], *path: str) -> str:
    cur: Any = claim
    for key in path:
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(key)
    return str(cur or "").strip() if cur is not None else ""


def _pick_claim_bool(claim: dict[str, Any], *path: str) -> bool:
    cur: Any = claim
    for key in path:
        if not isinstance(cur, dict):
            return False
        cur = cur.get(key)
    return bool(cur)


def _generate_ascii_key(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _get_appref_vekey1_override() -> str:
    raw = str(os.environ.get("ICSEE_APPREF_VEKEY1") or "").strip()
    if len(raw) != 64:
        return ""
    if not all(ch in (string.ascii_letters + string.digits) for ch in raw):
        return ""
    return raw


def _normalize_media_random_str(value: str) -> str:
    raw = str(value or "").strip()
    if len(raw) != 64:
        return ""
    if not all(ch in (string.ascii_letters + string.digits) for ch in raw):
        return ""
    return raw


def _xm_md5_encrypt_value(value: str) -> str:
    raw = (value or "").encode("utf-8")
    digest = hashlib.md5(raw).digest()
    chars: list[str] = []
    for idx in range(8):
        val = (digest[idx * 2] + digest[idx * 2 + 1]) % 62
        if val < 10:
            chars.append(chr(val + ord("0")))
        elif val < 36:
            chars.append(chr(val + ord("7")))
        else:
            chars.append(chr(val + ord("=")))
    return "".join(chars)


def _dh_md5_encrypt_value(value: str, random_a: str, random_b: str) -> str:
    return _xm_md5_encrypt_value(f"{random_a}{value or ''}{random_b}")


def _md5_encrypt_value(value: str, use_dh: bool, random_a: str, random_b: str) -> str:
    if use_dh and random_a and random_b:
        return _dh_md5_encrypt_value(value, random_a, random_b)
    return _xm_md5_encrypt_value(value)


def _token_encrypt_value(value: str, use_dh: bool, random_a: str, random_b: str) -> str:
    if use_dh and random_a and random_b:
        return _dh_md5_encrypt_value(value, random_a, random_b)
    return value or ""


def _import_sdk_rsa_key(public_key: str):
    if not _crypto_ready():
        return None
    key = str(public_key or "").strip()
    if not key:
        return None
    try:
        if "BEGIN PUBLIC KEY" in key:
            return _RSA.import_key(key)
        if "," in key:
            modulus_hex, exponent_hex = key.split(",", 1)
            modulus = int(modulus_hex.strip(), 16)
            exponent = int(exponent_hex.strip(), 16)
            return _RSA.construct((modulus, exponent))
        return _RSA.import_key(_normalize_public_key(key))
    except Exception:
        return None


def _rsa_v15_encrypt_hex(value: str, public_key: str) -> str:
    rsa_key = _import_sdk_rsa_key(public_key)
    if rsa_key is None or _PKCS1_v1_5 is None:
        return ""
    try:
        cipher = _PKCS1_v1_5.new(rsa_key)
        encrypted = cipher.encrypt((value or "").encode("utf-8"))
        return encrypted.hex().upper()
    except Exception:
        return ""


def _aes_cbc_zero_pad_encrypt_base64(raw: bytes, key_text: str) -> str:
    if _AES is None:
        return ""
    key_bytes = (key_text or "").encode("utf-8")
    if len(key_bytes) not in (16, 24, 32):
        return ""
    if not raw:
        return ""
    padded_len = ((len(raw) + 15) // 16) * 16
    padded = raw.ljust(padded_len, b"\x00")
    try:
        cipher = _AES.new(key_bytes, _AES.MODE_CBC, iv=b"\x00" * 16)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode("ascii")
    except Exception:
        return ""


def _reverse_fixed_16_key(value: str) -> bytes:
    raw = (value or "").encode("utf-8", errors="ignore")[:16]
    return raw[::-1]


def _aes_ecb_decrypt_base64(raw_text: str, key_bytes: bytes) -> bytes:
    if _AES is None or len(key_bytes) != 16:
        return b""
    try:
        ciphertext = base64.b64decode(str(raw_text or "").strip())
    except Exception:
        return b""
    if not ciphertext or (len(ciphertext) % 16) != 0:
        return b""
    try:
        plain = _AES.new(key_bytes, _AES.MODE_ECB).decrypt(ciphertext)
    except Exception:
        return b""
    if plain:
        pad = plain[-1]
        if 1 <= pad <= 16 and plain.endswith(bytes([pad]) * pad):
            plain = plain[:-pad]
    return plain.rstrip(b"\x00")


def derive_futurehome_token_username(device_id: str, admin_token: str) -> str:
    key_bytes = _reverse_fixed_16_key(device_id)
    if len(key_bytes) != 16:
        return ""
    plain = _aes_ecb_decrypt_base64(admin_token, key_bytes)
    if not plain:
        return ""
    try:
        return plain.decode("utf-8").strip()
    except Exception:
        return plain.decode("latin-1", errors="ignore").strip()


def build_6611_login_candidate(
    *,
    claim_source: Any,
    device_id: str = "",
    username: str,
    password: str,
    admin_token: str = "",
    login_type: str = "DVRIP-Web",
    token_username: str = "",
    random_a: str = "",
    random_b: str = "",
    user_agent: str = "",
    communicate_key: str = "",
    transport_key: str = "",
    media_random_str: str = "",
    vekey1: str = "",
    mode: str = "auto",
    msg_type: int = 0,
    session_id: int = 0,
    msg_id: int = 0x80,
    unk: int = 0x63,
    cmd: int = 0x03E8,
) -> dict[str, Any]:
    claim = _claim_json_dict(claim_source)
    result: dict[str, Any] = {
        "status": "error",
        "mode": mode,
        "frame": {
            "msg_type": msg_type,
            "session_id": session_id,
            "msg_id": msg_id,
            "unk": unk,
            "cmd": cmd,
        },
    }
    if not _crypto_ready():
        result["error"] = "pycryptodome_unavailable"
        return result

    encrypt_algo = _pick_claim_str(claim, "EncryptAlgo")
    public_key = _pick_claim_str(claim, "PublicKey")
    random_b = (random_b or _pick_claim_str(claim, "DHParameter", "RandomStrB")).strip()
    login_flags = claim.get("LoginEncryptionType") if isinstance(claim.get("LoginEncryptionType"), dict) else {}
    data_flags = claim.get("DataEncryptionType") if isinstance(claim.get("DataEncryptionType"), dict) else {}
    use_md5_dh = bool(login_flags.get("MD5_DH")) and bool(random_a) and bool(random_b)
    use_token_dh = bool(login_flags.get("TOKEN_DH")) and bool(random_a) and bool(random_b)
    use_token = False
    resolved_mode = (mode or "auto").strip().lower()
    if resolved_mode == "token":
        use_token = True
    elif resolved_mode == "password":
        use_token = False
    else:
        use_token = bool(admin_token) and bool(login_flags.get("TOKEN"))
        resolved_mode = "token" if use_token else "password"

    media_random_required = bool(data_flags.get("VEKEY1"))
    data_encryption_enabled = bool(data_flags.get("AESV2") or data_flags.get("AES") or media_random_required)
    raw_comm_key = (communicate_key or "").strip()
    if data_encryption_enabled and not raw_comm_key:
        raw_comm_key = _generate_ascii_key(16)
    raw_transport_key = (transport_key or "").strip()
    if data_encryption_enabled and not raw_transport_key:
        raw_transport_key = SPECIAL_LOGIN_AES_KEY.decode("ascii")
    raw_media_random_str = _normalize_media_random_str(media_random_str)
    if media_random_required and not raw_media_random_str:
        raw_media_random_str = _generate_ascii_key(64)
    raw_vekey1 = _normalize_media_random_str(vekey1)
    if media_random_required and not raw_vekey1:
        raw_vekey1 = _generate_ascii_key(64)

    login_type = (login_type or "DVRIP-Web").strip() or "DVRIP-Web"
    username = (username or "").strip()
    password = password or ""
    admin_token = (admin_token or "").strip()
    token_username = (token_username or "").strip()
    derived_token_username = ""
    inner_payload: dict[str, Any] = {
        "EncryptType": "",
        "LoginType": login_type,
        "UserName": "",
        "PassWord": "",
    }

    if use_token:
        token_value = _token_encrypt_value(admin_token, use_token_dh, random_a, random_b)
        if not token_username and login_type == "DVRIP-FutureHome":
            derived_token_username = derive_futurehome_token_username(device_id, admin_token)
            token_username = derived_token_username or _generate_ascii_key(16)
        inner_payload["EncryptType"] = "TOKEN_DH" if use_token_dh else "TOKEN"
        inner_payload["UserName"] = token_username or token_value or username
        inner_payload["PassWord"] = ""
    else:
        password_value = _md5_encrypt_value(password, use_md5_dh, random_a, random_b)
        encrypt_type = "MD5_DH" if use_md5_dh else "MD5"
        user_value = username
        if encrypt_algo.upper() == "RSA_V1.5" and public_key:
            rsa_user = _rsa_v15_encrypt_hex(username, public_key)
            rsa_pass = _rsa_v15_encrypt_hex(password_value, public_key)
            if rsa_user and rsa_pass:
                user_value = rsa_user
                password_value = rsa_pass
                encrypt_type = "RSA_V1.5"
        inner_payload["EncryptType"] = encrypt_type
        inner_payload["UserName"] = user_value
        inner_payload["PassWord"] = password_value

    if data_encryption_enabled and raw_comm_key:
        communicate_value = raw_comm_key
        if encrypt_algo.upper() == "RSA_V1.5" and public_key:
            rsa_comm = _rsa_v15_encrypt_hex(raw_comm_key, public_key)
            if rsa_comm:
                communicate_value = rsa_comm
        inner_payload["CommunicateKey"] = communicate_value
    if user_agent:
        inner_payload["User-Agent"] = user_agent

    inner_json = json.dumps(inner_payload, ensure_ascii=False, separators=(",", ":"))
    transport_payload_text = inner_json
    transport_mode = "plain"
    if data_encryption_enabled and raw_transport_key:
        encrypted_b64 = _aes_cbc_zero_pad_encrypt_base64(inner_json.encode("utf-8"), raw_transport_key)
        if not encrypted_b64:
            result["error"] = "login_aes_encrypt_failed"
            result["candidate_json"] = inner_payload
            result["candidate_json_text"] = inner_json
            return result
        transport_payload_text = encrypted_b64
        transport_mode = "aes_cbc_zero_pad_base64"

    payload_bytes = transport_payload_text.encode("utf-8") + b"\x00"
    frame_bytes = _build_tcp_frame(
        msg_type=msg_type,
        session_id=session_id,
        msg_id=msg_id,
        code=0,
        payload=payload_bytes,
        unk=unk,
        cmd=cmd,
    )
    result.update(
        {
            "status": "ok",
            "mode": resolved_mode,
            "claim_summary": {
                "encrypt_algo": encrypt_algo,
                "has_public_key": bool(public_key),
                "random_a": random_a,
                "random_b": random_b,
                "token_supported": bool(login_flags.get("TOKEN")),
                "token_dh_supported": bool(login_flags.get("TOKEN_DH")),
                "md5_dh_supported": bool(login_flags.get("MD5_DH")),
                "data_encryption": {
                    "AES": bool(data_flags.get("AES")),
                    "AESV2": bool(data_flags.get("AESV2")),
                    "VEKEY1": media_random_required,
                },
            },
            "candidate_json": inner_payload,
            "candidate_json_text": inner_json,
            "derived_token_username": derived_token_username,
            "communicate_key_raw": raw_comm_key,
            "transport_key_raw": raw_transport_key,
            "media_random_str_raw": raw_media_random_str,
            "vekey1_raw": raw_vekey1,
            "transport": {
                "mode": transport_mode,
                "payload_len": len(payload_bytes),
                "payload_text": transport_payload_text,
                "payload_b64_len": len(base64.b64decode(transport_payload_text)) if transport_mode != "plain" else 0,
            },
            "frame": {
                "msg_type": msg_type,
                "session_id": session_id,
                "msg_id": msg_id,
                "unk": unk,
                "cmd": cmd,
                "payload_len": len(payload_bytes),
                "frame_len": len(frame_bytes),
                "frame_hex": frame_bytes.hex(),
            },
        }
    )
    return result


def build_opmonitor_media_plaintext(
    *,
    action: str = "Start",
    channel: int = 0,
    stream_type: str = "Main",
    trans_mode: str = "TCP",
    combine_mode: str = "CONNECT_ALL",
    session_hex: str = "",
    session_id_value: str = "",
    session_id_mode: str = "hex",
    action1: str = "",
    extra1: str = "",
    multi_channel: list[int] | None = None,
    subconn_id: str = "",
    extra_parameters: dict[str, Any] | None = None,
    include_channel: bool = True,
    include_combine_mode: bool = True,
    include_stream_type: bool = True,
    include_trans_mode: bool = True,
) -> str:
    parameter: dict[str, Any] = {}
    if include_channel:
        parameter["Channel"] = int(channel)
    if include_combine_mode:
        parameter["CombinMode"] = combine_mode
    if include_stream_type:
        parameter["StreamType"] = stream_type
    if include_trans_mode:
        parameter["TransMode"] = trans_mode
    if extra1:
        parameter["Extra1"] = extra1
    if multi_channel:
        parameter.pop("Channel", None)
        parameter["SubConnID"] = subconn_id or _generate_ascii_key(32)
        parameter["MultiChannel"] = [int(item) for item in multi_channel]
    if extra_parameters:
        parameter.update(dict(extra_parameters))

    opmonitor: dict[str, Any] = {
        "Action": action,
        "Parameter": parameter,
    }
    if action1:
        opmonitor["Action1"] = action1

    payload: dict[str, Any] = {
        "Name": "OPMonitor",
        "OPMonitor": opmonitor,
    }
    session_mode = str(session_id_mode or "hex").strip().lower()
    if session_id_value:
        payload["SessionID"] = session_id_value
    elif session_mode == "random32":
        payload["SessionID"] = _generate_ascii_key(32)
    elif session_hex:
        payload["SessionID"] = session_hex
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def build_6611_dataenc_followup(
    *,
    cmd: int,
    plain_payload_text: str,
    communicate_key: str,
    msg_type: int = 0,
    session_id: int = 0,
    msg_id: int = 40,
    unk: int = 0,
) -> dict[str, Any]:
    encrypted_b64 = _aes_cbc_zero_pad_encrypt_base64(plain_payload_text.encode("utf-8"), communicate_key)
    return {
        "msg_type": int(msg_type),
        "session_id": int(session_id),
        "msg_id": int(msg_id),
        "unk": int(unk),
        "cmd": int(cmd),
        "code": 0,
        "code_endian": "be",
        "payload_text": encrypted_b64,
        "payload_bytes": encrypted_b64.encode("utf-8") + b"\x00",
        "plain_payload_text": plain_payload_text,
    }


def build_ptl_name_plaintext(name: str) -> str:
    return json.dumps({"Name": str(name)}, ensure_ascii=False, separators=(",", ":"))


def build_named_session_plaintext(
    name: str,
    *,
    session_id: int | None = None,
    session_id_text: str = "",
    session_width: int = 10,
    session_first: bool = False,
    payload_body: Any | None = None,
) -> str:
    payload: dict[str, Any] = {}
    session_text = str(session_id_text or "").strip()
    if not session_text and session_id is not None:
        session_text = _format_session_hex(int(session_id), width=int(session_width))
    if session_first and session_text:
        payload["SessionID"] = session_text
    payload["Name"] = str(name)
    if payload_body is not None:
        payload[str(name)] = payload_body
    if (not session_first) and session_text:
        payload["SessionID"] = session_text
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def build_media_force_iframe_plaintext(session_id: int) -> str:
    payload = {
        "Name": "",
        "SessionID": f"0x{int(session_id):010X}",
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def build_named_ptl_followup(
    *,
    cmd: int,
    name: str,
    communicate_key: str,
    session_id: int,
    msg_id: int,
    unk: int = 0,
) -> dict[str, Any]:
    return build_6611_dataenc_followup(
        cmd=int(cmd),
        plain_payload_text=build_ptl_name_plaintext(name),
        communicate_key=communicate_key,
        msg_type=0,
        session_id=int(session_id),
        msg_id=int(msg_id),
        unk=int(unk),
    )


def build_named_session_followup(
    *,
    cmd: int,
    name: str,
    communicate_key: str,
    session_id: int,
    msg_id: int,
    unk: int = 0,
    session_id_text: str = "",
    session_width: int = 10,
    session_first: bool = False,
    payload_body: Any | None = None,
) -> dict[str, Any]:
    return build_6611_dataenc_followup(
        cmd=int(cmd),
        plain_payload_text=build_named_session_plaintext(
            str(name),
            session_id=int(session_id),
            session_id_text=str(session_id_text or ""),
            session_width=int(session_width),
            session_first=bool(session_first),
            payload_body=payload_body,
        ),
        communicate_key=communicate_key,
        msg_type=0,
        session_id=int(session_id),
        msg_id=int(msg_id),
        unk=int(unk),
    )


def build_opt_upload_data_plaintext(
    *,
    session_id: int,
    upload_data_type: int,
    specific_type: Any | None = None,
) -> str:
    opt_payload: dict[str, Any] = {
        "UpLoadDataType": int(upload_data_type),
    }
    if specific_type is not None:
        opt_payload["SpecificType"] = specific_type
    payload = {
        "Name": "OPTUpData",
        "OPTUpData": opt_payload,
        "SessionID": f"0x{int(session_id):010X}",
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def build_opt_upload_data_followup(
    *,
    session_id: int,
    msg_id: int,
    communicate_key: str,
    upload_data_type: int,
    specific_type: Any | None = None,
    stop: bool = False,
    unk: int = 0,
) -> dict[str, Any]:
    return build_6611_dataenc_followup(
        cmd=0x064C if stop else 0x064A,
        plain_payload_text=build_opt_upload_data_plaintext(
            session_id=int(session_id),
            upload_data_type=int(upload_data_type),
            specific_type=specific_type,
        ),
        communicate_key=communicate_key,
        msg_type=0,
        session_id=int(session_id),
        msg_id=int(msg_id),
        unk=int(unk),
    )


def build_controller_auto_followups(
    *,
    profile: str,
    runtime_session_id: int,
    runtime_msg_id: int,
    communicate_key: str,
    media_random_str: str = "",
    vekey1: str = "",
    device_id: str = "",
    channel: int,
    stream_type: str = "Main",
    trans_mode: str = "TCP",
    combine_mode: str = "CONNECT_ALL",
) -> list[dict[str, Any]]:
    selected = (profile or "first_582_start_random32").strip().lower()
    if selected == "app_reference_first_6611":
        runtime_msg_id = 64
    if not communicate_key:
        return []

    def _mark_followup(
        followup: dict[str, Any],
        profile_name: str,
        *,
        delay_before: float | None = None,
        plain_payload_text: str | None = None,
        burst_group: str | None = None,
    ) -> dict[str, Any]:
        followup["send_phase"] = "post_login_auto"
        followup["controller_profile"] = profile_name
        if delay_before is not None and delay_before > 0:
            followup["delay_before"] = float(delay_before)
        if plain_payload_text:
            followup["plain_payload_text"] = plain_payload_text
        if burst_group:
            followup["burst_group"] = str(burst_group)
        return followup

    def _build_update_config_followups(
        *,
        profile_name: str,
        msg_base: int,
        config_delay: float = 0.0,
        repeat_550_delay: float | None = None,
        iframe_retry_delay: float | None = None,
    ) -> list[dict[str, Any]]:
        config_followups: list[dict[str, Any]] = []
        followup_3fc = build_named_ptl_followup(
            cmd=0x03FC,
            name="SystemInfo",
            communicate_key=communicate_key,
            session_id=int(runtime_session_id),
            msg_id=int(msg_base),
            unk=0,
        )
        config_followups.append(
            _mark_followup(followup_3fc, profile_name, delay_before=config_delay)
        )

        followup_550 = build_named_ptl_followup(
            cmd=0x0550,
            name="SystemFunction",
            communicate_key=communicate_key,
            session_id=int(runtime_session_id),
            msg_id=int(msg_base) + 8,
            unk=0,
        )
        config_followups.append(_mark_followup(followup_550, profile_name))

        followup_412 = build_named_ptl_followup(
            cmd=0x0412,
            name="fVideo.AudioSupportType",
            communicate_key=communicate_key,
            session_id=int(runtime_session_id),
            msg_id=int(msg_base) + 16,
            unk=0,
        )
        config_followups.append(_mark_followup(followup_412, profile_name))

        if repeat_550_delay is not None:
            repeat_550 = build_named_ptl_followup(
                cmd=0x0550,
                name="SystemFunction",
                communicate_key=communicate_key,
                session_id=int(runtime_session_id),
                msg_id=int(msg_base) + 24,
                unk=0,
            )
            config_followups.append(
                _mark_followup(repeat_550, profile_name, delay_before=repeat_550_delay)
            )

        if iframe_retry_delay is not None:
            retry_61a = build_6611_dataenc_followup(
                cmd=0x061A,
                plain_payload_text=build_media_force_iframe_plaintext(int(runtime_session_id)),
                communicate_key=communicate_key,
                msg_type=0,
                session_id=int(runtime_session_id),
                msg_id=int(msg_base) + 32,
                unk=256,
            )
            config_followups.append(
                _mark_followup(retry_61a, profile_name, delay_before=iframe_retry_delay)
            )
        return config_followups

    def _build_static_cipher_followup(
        *,
        cmd: int,
        payload_text: str,
        msg_id: int,
        unk: int = 0,
    ) -> dict[str, Any]:
        return {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(msg_id),
            "unk": int(unk),
            "cmd": int(cmd),
            "code": 0,
            "code_endian": "be",
            "payload_text": str(payload_text),
            "payload_bytes": str(payload_text).encode("ascii") + b"\x00",
        }

    if selected not in {
        "first_582_start_random32",
        "start_random32",
        "first_582",
        "first_582_then_61a_static",
        "first_582_plus_61a_static",
        "first_582_61a",
        "first_582_61a_550_static",
        "first_582_61a_64a_static",
        "first_582_61a_second582_channel_only_start",
        "first_582_61a_second582_channel_only_start_64a_static",
        "first_582_61a_second582_channel_only_start_64c_static",
        "first_582_61a_second582_channel_only_start_3fc_static",
        "first_582_61a_second582_channel_only_start_412a_static",
        "first_582_61a_second582_channel_only_start_412b_static",
        "first_582_61a_second582_channel_only_start_412c_static",
        "first_582_61a_second582_channel_only_start_550b_static",
        "first_582_61a_second582_channel_only_start_550c_static",
        "first_582_61a_second582_channel_only_start_3fc_ptl",
        "first_582_61a_second582_channel_only_start_550_ptl",
        "first_582_61a_second582_channel_only_start_412_ptl",
        "first_582_61a_second582_channel_only_start_update_config_ptl",
        "first_582_61a_second582_channel_only_start_update_config_ptl_iframe_retry",
        "first_582_61a_waitfree_update_config_ptl",
        "first_582_61a_waitfree_update_config_ptl_550_repeat",
        "first_582_61a_waitfree_update_config_ptl_550_repeat_iframe_retry",
        "first_582_61a_waitfree_update_config_ptl_64a_type2",
        "first_582_61a_waitfree_update_config_ptl_64a_type2_550_repeat_iframe_retry",
        "first_582_61a_waitfree_update_config_ptl_64a64c_type2",
        "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582",
        "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582_second64c",
        "historical_full_dynamic_second582",
        "historical_full_raw_second582",
        "historical_order_built_queries_dynamic_second582",
        "historical_order_built_queries_dynamic_second582_nostop",
        "app_reference_first_6611",
    }:
        return []

    out: list[dict[str, Any]] = []
    if selected != "app_reference_first_6611":
        plain = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=True,
            include_stream_type=True,
            include_trans_mode=True,
        )
        followup = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id),
            unk=0,
        )
        _mark_followup(followup, "first_582_start_random32", plain_payload_text=plain)
        out = [followup]

    if selected in {
        "first_582_then_61a_static",
        "first_582_plus_61a_static",
        "first_582_61a",
        "first_582_61a_550_static",
        "first_582_61a_64a_static",
        "first_582_61a_waitfree_update_config_ptl",
        "first_582_61a_waitfree_update_config_ptl_550_repeat",
        "first_582_61a_waitfree_update_config_ptl_550_repeat_iframe_retry",
        "first_582_61a_waitfree_update_config_ptl_64a_type2",
        "first_582_61a_waitfree_update_config_ptl_64a_type2_550_repeat_iframe_retry",
        "first_582_61a_waitfree_update_config_ptl_64a64c_type2",
        "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582",
        "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582_second64c",
        "historical_full_dynamic_second582",
        "historical_full_raw_second582",
        "historical_order_built_queries_dynamic_second582",
        "first_582_61a_second582_channel_only_start",
        "first_582_61a_second582_channel_only_start_64a_static",
        "first_582_61a_second582_channel_only_start_64c_static",
        "first_582_61a_second582_channel_only_start_3fc_static",
        "first_582_61a_second582_channel_only_start_412a_static",
        "first_582_61a_second582_channel_only_start_412b_static",
        "first_582_61a_second582_channel_only_start_412c_static",
        "first_582_61a_second582_channel_only_start_550b_static",
        "first_582_61a_second582_channel_only_start_550c_static",
        "first_582_61a_second582_channel_only_start_3fc_ptl",
        "first_582_61a_second582_channel_only_start_550_ptl",
        "first_582_61a_second582_channel_only_start_412_ptl",
        "first_582_61a_second582_channel_only_start_update_config_ptl",
        "first_582_61a_second582_channel_only_start_update_config_ptl_iframe_retry",
    }:
        followup_61a = build_6611_dataenc_followup(
            cmd=0x061A,
            plain_payload_text=build_media_force_iframe_plaintext(int(runtime_session_id)),
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 8,
            unk=256,
        )
        _mark_followup(followup_61a, "first_582_then_61a_static")
        out.append(followup_61a)

    if selected == "first_582_61a_550_static":
        followup_550 = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 16,
            "unk": 0,
            "cmd": 0x0550,
            "code": 0,
            "code_endian": "be",
            "payload_text": "BZAX9Q+3lrgflzLO1nKiNJyvqrr2h2w8x+84d7lgar5vdyk9xJzhkgG/AiiVQfWB",
            "payload_bytes": b"BZAX9Q+3lrgflzLO1nKiNJyvqrr2h2w8x+84d7lgar5vdyk9xJzhkgG/AiiVQfWB\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_550_static",
        }
        out.append(followup_550)

    if selected == "first_582_61a_64a_static":
        followup_64a = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 16,
            "unk": 0,
            "cmd": 0x064A,
            "code": 0,
            "code_endian": "be",
            "payload_text": "Q5Xz1BHB0lpMjoVZPrZKLJvmDfbv8Fx6zQJRBtTlMQKJvAOeaqPsDbpEEuXTlAsJhEAaGBgA97NFxC4n3c7Oqr5bGjlRf9RaRkQ4HSG2LRCDJHZNj0szkI7M5PKsf15++yt3pfDhW0YCGrv6RZfgPQ==",
            "payload_bytes": b"Q5Xz1BHB0lpMjoVZPrZKLJvmDfbv8Fx6zQJRBtTlMQKJvAOeaqPsDbpEEuXTlAsJhEAaGBgA97NFxC4n3c7Oqr5bGjlRf9RaRkQ4HSG2LRCDJHZNj0szkI7M5PKsf15++yt3pfDhW0YCGrv6RZfgPQ==\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_64a_static",
        }
        out.append(followup_64a)

    if selected == "first_582_61a_second582_channel_only_start":
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        followup_second_582 = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain_second_582,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 16,
            unk=0,
        )
        followup_second_582["send_phase"] = "post_login_auto"
        followup_second_582["controller_profile"] = "first_582_61a_second582_channel_only_start"
        followup_second_582["plain_payload_text"] = plain_second_582
        out.append(followup_second_582)

    if selected == "first_582_61a_second582_channel_only_start_64a_static":
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        followup_second_582 = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain_second_582,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 16,
            unk=0,
        )
        followup_second_582["send_phase"] = "post_login_auto"
        followup_second_582["controller_profile"] = "first_582_61a_second582_channel_only_start_64a_static"
        followup_second_582["plain_payload_text"] = plain_second_582
        out.append(followup_second_582)

        followup_64a = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 24,
            "unk": 0,
            "cmd": 0x064A,
            "code": 0,
            "code_endian": "be",
            "payload_text": "Q5Xz1BHB0lpMjoVZPrZKLJvmDfbv8Fx6zQJRBtTlMQKJvAOeaqPsDbpEEuXTlAsJhEAaGBgA97NFxC4n3c7Oqr5bGjlRf9RaRkQ4HSG2LRCDJHZNj0szkI7M5PKsf15++yt3pfDhW0YCGrv6RZfgPQ==",
            "payload_bytes": b"Q5Xz1BHB0lpMjoVZPrZKLJvmDfbv8Fx6zQJRBtTlMQKJvAOeaqPsDbpEEuXTlAsJhEAaGBgA97NFxC4n3c7Oqr5bGjlRf9RaRkQ4HSG2LRCDJHZNj0szkI7M5PKsf15++yt3pfDhW0YCGrv6RZfgPQ==\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_second582_channel_only_start_64a_static",
        }
        out.append(followup_64a)

    if selected == "first_582_61a_second582_channel_only_start_64c_static":
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        followup_second_582 = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain_second_582,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 16,
            unk=0,
        )
        followup_second_582["send_phase"] = "post_login_auto"
        followup_second_582["controller_profile"] = "first_582_61a_second582_channel_only_start_64c_static"
        followup_second_582["plain_payload_text"] = plain_second_582
        out.append(followup_second_582)

        followup_64c = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 24,
            "unk": 0,
            "cmd": 0x064C,
            "code": 0,
            "code_endian": "be",
            "payload_text": "Q5Xz1BHB0lpMjoVZPrZKLJvmDfbv8Fx6zQJRBtTlMQKJvAOeaqPsDbpEEuXTlAsJhEAaGBgA97NFxC4n3c7Oqr5bGjlRf9RaRkQ4HSG2LRCDJHZNj0szkI7M5PKsf15++yt3pfDhW0YCGrv6RZfgPQ==",
            "payload_bytes": b"Q5Xz1BHB0lpMjoVZPrZKLJvmDfbv8Fx6zQJRBtTlMQKJvAOeaqPsDbpEEuXTlAsJhEAaGBgA97NFxC4n3c7Oqr5bGjlRf9RaRkQ4HSG2LRCDJHZNj0szkI7M5PKsf15++yt3pfDhW0YCGrv6RZfgPQ==\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_second582_channel_only_start_64c_static",
        }
        out.append(followup_64c)

    if selected == "first_582_61a_second582_channel_only_start_3fc_static":
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        followup_second_582 = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain_second_582,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 16,
            unk=0,
        )
        followup_second_582["send_phase"] = "post_login_auto"
        followup_second_582["controller_profile"] = "first_582_61a_second582_channel_only_start_3fc_static"
        followup_second_582["plain_payload_text"] = plain_second_582
        out.append(followup_second_582)

        followup_3fc = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 24,
            "unk": 0,
            "cmd": 0x03FC,
            "code": 0,
            "code_endian": "be",
            "payload_text": "KINIAMRxXzmm4MCN6tgJisdvrSAV75fZRsPae/+1WIuR1OiEVOC2AXuKm36QYzmB+00M49Vur4K8tUwQdU4Bug==",
            "payload_bytes": b"KINIAMRxXzmm4MCN6tgJisdvrSAV75fZRsPae/+1WIuR1OiEVOC2AXuKm36QYzmB+00M49Vur4K8tUwQdU4Bug==\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_second582_channel_only_start_3fc_static",
        }
        out.append(followup_3fc)

    if selected == "first_582_61a_second582_channel_only_start_412a_static":
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        followup_second_582 = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain_second_582,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 16,
            unk=0,
        )
        followup_second_582["send_phase"] = "post_login_auto"
        followup_second_582["controller_profile"] = "first_582_61a_second582_channel_only_start_412a_static"
        followup_second_582["plain_payload_text"] = plain_second_582
        out.append(followup_second_582)

        followup_412 = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 24,
            "unk": 0,
            "cmd": 0x0412,
            "code": 0,
            "code_endian": "be",
            "payload_text": "6FWhBV8u06ohy8gGrsUs4chHHKF977L46gicb1vXkUmaI0Lhu9GXbNCQ+6hgF1zqXC4hzHnTA5fGrgny1AgLoQ==",
            "payload_bytes": b"6FWhBV8u06ohy8gGrsUs4chHHKF977L46gicb1vXkUmaI0Lhu9GXbNCQ+6hgF1zqXC4hzHnTA5fGrgny1AgLoQ==\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_second582_channel_only_start_412a_static",
        }
        out.append(followup_412)

    if selected == "first_582_61a_second582_channel_only_start_412b_static":
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        followup_second_582 = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain_second_582,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 16,
            unk=0,
        )
        followup_second_582["send_phase"] = "post_login_auto"
        followup_second_582["controller_profile"] = "first_582_61a_second582_channel_only_start_412b_static"
        followup_second_582["plain_payload_text"] = plain_second_582
        out.append(followup_second_582)

        followup_412 = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 24,
            "unk": 0,
            "cmd": 0x0412,
            "code": 0,
            "code_endian": "be",
            "payload_text": "ZtBapWrWQxtNbFtOfEkJbq2v5fsl73bSA/GZpjZkLGKljiHPeRDinkxrOYCvnUOunN47TIqpCW7SrTs3TrC2Sw==",
            "payload_bytes": b"ZtBapWrWQxtNbFtOfEkJbq2v5fsl73bSA/GZpjZkLGKljiHPeRDinkxrOYCvnUOunN47TIqpCW7SrTs3TrC2Sw==\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_second582_channel_only_start_412b_static",
        }
        out.append(followup_412)

    if selected == "first_582_61a_second582_channel_only_start_412c_static":
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        followup_second_582 = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain_second_582,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 16,
            unk=0,
        )
        followup_second_582["send_phase"] = "post_login_auto"
        followup_second_582["controller_profile"] = "first_582_61a_second582_channel_only_start_412c_static"
        followup_second_582["plain_payload_text"] = plain_second_582
        out.append(followup_second_582)

        followup_412 = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 24,
            "unk": 0,
            "cmd": 0x0412,
            "code": 0,
            "code_endian": "be",
            "payload_text": "wTMP9Gdi/rzLZQuX+uAkB9ENP0silFvCBumCpfHeIu/l8kzXfTZbDht/vUFGdIXgYvP9Id7U6PDQPkjt4zZkjA==",
            "payload_bytes": b"wTMP9Gdi/rzLZQuX+uAkB9ENP0silFvCBumCpfHeIu/l8kzXfTZbDht/vUFGdIXgYvP9Id7U6PDQPkjt4zZkjA==\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_second582_channel_only_start_412c_static",
        }
        out.append(followup_412)

    if selected == "first_582_61a_second582_channel_only_start_550b_static":
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        followup_second_582 = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain_second_582,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 16,
            unk=0,
        )
        followup_second_582["send_phase"] = "post_login_auto"
        followup_second_582["controller_profile"] = "first_582_61a_second582_channel_only_start_550b_static"
        followup_second_582["plain_payload_text"] = plain_second_582
        out.append(followup_second_582)

        followup_550 = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 24,
            "unk": 0,
            "cmd": 0x0550,
            "code": 0,
            "code_endian": "be",
            "payload_text": "MChR1v+Vc5sAMqui7fVD1UGWFeRW/ZddpU3ZbUZXZH/pXbtK8JBmhtwpTE1RlWiKwY3Y6IqOSn8nkJUdMzD35Q==",
            "payload_bytes": b"MChR1v+Vc5sAMqui7fVD1UGWFeRW/ZddpU3ZbUZXZH/pXbtK8JBmhtwpTE1RlWiKwY3Y6IqOSn8nkJUdMzD35Q==\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_second582_channel_only_start_550b_static",
        }
        out.append(followup_550)

    if selected == "first_582_61a_second582_channel_only_start_550c_static":
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        followup_second_582 = build_6611_dataenc_followup(
            cmd=0x0582,
            plain_payload_text=plain_second_582,
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 16,
            unk=0,
        )
        followup_second_582["send_phase"] = "post_login_auto"
        followup_second_582["controller_profile"] = "first_582_61a_second582_channel_only_start_550c_static"
        followup_second_582["plain_payload_text"] = plain_second_582
        out.append(followup_second_582)

        followup_550 = {
            "msg_type": 0,
            "session_id": int(runtime_session_id),
            "msg_id": int(runtime_msg_id) + 24,
            "unk": 0,
            "cmd": 0x0550,
            "code": 0,
            "code_endian": "be",
            "payload_text": "VfbqRY6htKaOixcC5rSC73pZ5nmUbS7VOQJk3lfbmJD08q4LCGpYEQDOVY3pgrriO4/OTT9rj+5kAXXINFEK3A==",
            "payload_bytes": b"VfbqRY6htKaOixcC5rSC73pZ5nmUbS7VOQJk3lfbmJD08q4LCGpYEQDOVY3pgrriO4/OTT9rj+5kAXXINFEK3A==\x00",
            "send_phase": "post_login_auto",
            "controller_profile": "first_582_61a_second582_channel_only_start_550c_static",
        }
        out.append(followup_550)

    if selected == "first_582_61a_second582_channel_only_start_3fc_ptl":
        followup_3fc = build_named_ptl_followup(
            cmd=0x03FC,
            name="SystemInfo",
            communicate_key=communicate_key,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 24,
            unk=0,
        )
        followup_3fc["send_phase"] = "post_login_auto"
        followup_3fc["controller_profile"] = "first_582_61a_second582_channel_only_start_3fc_ptl"
        out.append(followup_3fc)

    if selected == "first_582_61a_second582_channel_only_start_550_ptl":
        followup_550 = build_named_ptl_followup(
            cmd=0x0550,
            name="SystemFunction",
            communicate_key=communicate_key,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 24,
            unk=0,
        )
        followup_550["send_phase"] = "post_login_auto"
        followup_550["controller_profile"] = "first_582_61a_second582_channel_only_start_550_ptl"
        out.append(followup_550)

    if selected == "first_582_61a_second582_channel_only_start_412_ptl":
        followup_412 = build_named_ptl_followup(
            cmd=0x0412,
            name="fVideo.AudioSupportType",
            communicate_key=communicate_key,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 24,
            unk=0,
        )
        followup_412["send_phase"] = "post_login_auto"
        followup_412["controller_profile"] = "first_582_61a_second582_channel_only_start_412_ptl"
        out.append(followup_412)

    if selected in {
        "first_582_61a_waitfree_update_config_ptl",
        "first_582_61a_waitfree_update_config_ptl_550_repeat",
        "first_582_61a_waitfree_update_config_ptl_550_repeat_iframe_retry",
    }:
        out.extend(
            _build_update_config_followups(
                profile_name="first_582_61a_waitfree_update_config_ptl",
                msg_base=int(runtime_msg_id) + 16,
                config_delay=1.0,
                repeat_550_delay=0.6
                if selected
                in {
                    "first_582_61a_waitfree_update_config_ptl_550_repeat",
                    "first_582_61a_waitfree_update_config_ptl_550_repeat_iframe_retry",
                }
                else None,
                iframe_retry_delay=1.2
                if selected == "first_582_61a_waitfree_update_config_ptl_550_repeat_iframe_retry"
                else None,
            )
        )

    if selected in {
        "first_582_61a_waitfree_update_config_ptl_64a_type2",
        "first_582_61a_waitfree_update_config_ptl_64a_type2_550_repeat_iframe_retry",
        "first_582_61a_waitfree_update_config_ptl_64a64c_type2",
        "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582",
        "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582_second64c",
    }:
        out.extend(
            _build_update_config_followups(
                profile_name="first_582_61a_waitfree_update_config_ptl_64a_type2",
                msg_base=int(runtime_msg_id) + 16,
                config_delay=1.0,
            )
        )
        followup_64a = build_opt_upload_data_followup(
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 40,
            communicate_key=communicate_key,
            upload_data_type=2,
            specific_type=None,
            stop=False,
            unk=0,
        )
        out.append(
            _mark_followup(
                followup_64a,
                "first_582_61a_waitfree_update_config_ptl_64a_type2",
                delay_before=0.2,
                plain_payload_text=build_opt_upload_data_plaintext(
                    session_id=int(runtime_session_id),
                    upload_data_type=2,
                    specific_type=None,
                ),
            )
        )
        if selected in {
            "first_582_61a_waitfree_update_config_ptl_64a_type2_550_repeat_iframe_retry",
            "first_582_61a_waitfree_update_config_ptl_64a64c_type2",
            "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582",
        }:
            repeat_550 = build_named_ptl_followup(
                cmd=0x0550,
                name="SystemFunction",
                communicate_key=communicate_key,
                session_id=int(runtime_session_id),
                msg_id=int(runtime_msg_id) + 48,
                unk=0,
            )
            out.append(
                _mark_followup(
                    repeat_550,
                    "first_582_61a_waitfree_update_config_ptl_64a_type2",
                    delay_before=0.6,
                )
            )
            retry_61a = build_6611_dataenc_followup(
                cmd=0x061A,
                plain_payload_text=build_media_force_iframe_plaintext(int(runtime_session_id)),
                communicate_key=communicate_key,
                msg_type=0,
                session_id=int(runtime_session_id),
                msg_id=int(runtime_msg_id) + 56,
                unk=256,
            )
            out.append(
                _mark_followup(
                    retry_61a,
                    "first_582_61a_waitfree_update_config_ptl_64a_type2",
                    delay_before=1.2,
                )
            )
        if selected in {
            "first_582_61a_waitfree_update_config_ptl_64a64c_type2",
            "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582",
            "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582_second64c",
        }:
            followup_64c = build_opt_upload_data_followup(
                session_id=int(runtime_session_id),
                msg_id=int(runtime_msg_id) + 104,
                communicate_key=communicate_key,
                upload_data_type=2,
                specific_type=None,
                stop=True,
                unk=0,
            )
            out.append(
                _mark_followup(
                    followup_64c,
                    "first_582_61a_waitfree_update_config_ptl_64a_type2",
                    delay_before=1.0,
                    plain_payload_text=build_opt_upload_data_plaintext(
                        session_id=int(runtime_session_id),
                        upload_data_type=2,
                        specific_type=None,
                    ),
                )
            )
        if selected in {
            "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582",
            "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582_second64c",
        }:
            plain_second_582 = build_opmonitor_media_plaintext(
                action="Start",
                channel=int(channel),
                stream_type=stream_type or "Main",
                trans_mode=trans_mode or "TCP",
                combine_mode=combine_mode or "CONNECT_ALL",
                session_id_mode="random32",
                include_channel=True,
                include_combine_mode=False,
                include_stream_type=False,
                include_trans_mode=False,
            )
            followup_second_582 = build_6611_dataenc_followup(
                cmd=0x0582,
                plain_payload_text=plain_second_582,
                communicate_key=communicate_key,
                msg_type=0,
                session_id=int(runtime_session_id),
                msg_id=int(runtime_msg_id) + 112,
                unk=0,
            )
            out.append(
                _mark_followup(
                    followup_second_582,
                    "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582",
                    delay_before=0.5,
                    plain_payload_text=plain_second_582,
                )
            )
        if selected == "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582_second64c":
            late_followup_64c = build_opt_upload_data_followup(
                session_id=int(runtime_session_id),
                msg_id=int(runtime_msg_id) + 160,
                communicate_key=communicate_key,
                upload_data_type=2,
                specific_type=None,
                stop=True,
                unk=0,
            )
            out.append(
                _mark_followup(
                    late_followup_64c,
                    "first_582_61a_waitfree_update_config_ptl_64a64c_type2_second582_second64c",
                    delay_before=0.6,
                    plain_payload_text=build_opt_upload_data_plaintext(
                        session_id=int(runtime_session_id),
                        upload_data_type=2,
                        specific_type=None,
                    ),
                )
            )

    if selected in {
        "first_582_61a_second582_channel_only_start_update_config_ptl",
        "first_582_61a_second582_channel_only_start_update_config_ptl_iframe_retry",
    }:
        followup_3fc = build_named_ptl_followup(
            cmd=0x03FC,
            name="SystemInfo",
            communicate_key=communicate_key,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 24,
            unk=0,
        )
        followup_3fc["send_phase"] = "post_login_auto"
        followup_3fc["controller_profile"] = "first_582_61a_second582_channel_only_start_update_config_ptl"
        out.append(followup_3fc)

        followup_550 = build_named_ptl_followup(
            cmd=0x0550,
            name="SystemFunction",
            communicate_key=communicate_key,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 32,
            unk=0,
        )
        followup_550["send_phase"] = "post_login_auto"
        followup_550["controller_profile"] = "first_582_61a_second582_channel_only_start_update_config_ptl"
        out.append(followup_550)

        followup_412 = build_named_ptl_followup(
            cmd=0x0412,
            name="fVideo.AudioSupportType",
            communicate_key=communicate_key,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 40,
            unk=0,
        )
        followup_412["send_phase"] = "post_login_auto"
        followup_412["controller_profile"] = "first_582_61a_second582_channel_only_start_update_config_ptl"
        out.append(followup_412)

    if selected == "first_582_61a_second582_channel_only_start_update_config_ptl_iframe_retry":
        retry_61a_a = build_6611_dataenc_followup(
            cmd=0x061A,
            plain_payload_text=build_media_force_iframe_plaintext(int(runtime_session_id)),
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 48,
            unk=256,
        )
        retry_61a_a["send_phase"] = "post_login_auto"
        retry_61a_a["controller_profile"] = "first_582_61a_second582_channel_only_start_update_config_ptl_iframe_retry"
        retry_61a_a["delay_before"] = 3.2
        out.append(retry_61a_a)

        retry_61a_b = build_6611_dataenc_followup(
            cmd=0x061A,
            plain_payload_text=build_media_force_iframe_plaintext(int(runtime_session_id)),
            communicate_key=communicate_key,
            msg_type=0,
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 56,
            unk=256,
        )
        retry_61a_b["send_phase"] = "post_login_auto"
        retry_61a_b["controller_profile"] = "first_582_61a_second582_channel_only_start_update_config_ptl_iframe_retry"
        retry_61a_b["delay_before"] = 3.2
        out.append(retry_61a_b)

    if selected in {"historical_full_dynamic_second582", "historical_full_raw_second582"}:
        profile_name = selected
        static_schedule = [
            (0x0550, 16, "BZAX9Q+3lrgflzLO1nKiNJyvqrr2h2w8x+84d7lgar5vdyk9xJzhkgG/AiiVQfWB"),
            (0x064A, 24, None),
            (0x03FC, 32, "KINIAMRxXzmm4MCN6tgJisdvrSAV75fZRsPae/+1WIuR1OiEVOC2AXuKm36QYzmB+00M49Vur4K8tUwQdU4Bug=="),
            (0x0550, 40, "MChR1v+Vc5sAMqui7fVD1UGWFeRW/ZddpU3ZbUZXZH/pXbtK8JBmhtwpTE1RlWiKwY3Y6IqOSn8nkJUdMzD35Q=="),
            (0x0412, 48, "6FWhBV8u06ohy8gGrsUs4chHHKF977L46gicb1vXkUmaI0Lhu9GXbNCQ+6hgF1zqXC4hzHnTA5fGrgny1AgLoQ=="),
            (0x0412, 56, "ZtBapWrWQxtNbFtOfEkJbq2v5fsl73bSA/GZpjZkLGKljiHPeRDinkxrOYCvnUOunN47TIqpCW7SrTs3TrC2Sw=="),
            (0x0412, 64, "6FWhBV8u06ohy8gGrsUs4chHHKF977L46gicb1vXkUmaI0Lhu9GXbNCQ+6hgF1zqXC4hzHnTA5fGrgny1AgLoQ=="),
            (0x0412, 72, "ZtBapWrWQxtNbFtOfEkJbq2v5fsl73bSA/GZpjZkLGKljiHPeRDinkxrOYCvnUOunN47TIqpCW7SrTs3TrC2Sw=="),
            (0x0412, 80, "wTMP9Gdi/rzLZQuX+uAkB9ENP0silFvCBumCpfHeIu/l8kzXfTZbDht/vUFGdIXgYvP9Id7U6PDQPkjt4zZkjA=="),
            (0x0550, 88, "VfbqRY6htKaOixcC5rSC73pZ5nmUbS7VOQJk3lfbmJD08q4LCGpYEQDOVY3pgrriO4/OTT9rj+5kAXXINFEK3A=="),
            (0x064A, 96, None),
            (0x03FC, 104, "KINIAMRxXzmm4MCN6tgJisdvrSAV75fZRsPae/+1WIuR1OiEVOC2AXuKm36QYzmB+00M49Vur4K8tUwQdU4Bug=="),
            (0x064C, 112, None),
        ]
        for cmd, offset, payload_text in static_schedule:
            if cmd in {0x064A, 0x064C}:
                followup = build_opt_upload_data_followup(
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + offset,
                    communicate_key=communicate_key,
                    upload_data_type=2,
                    specific_type=None,
                    stop=(cmd == 0x064C),
                    unk=0,
                )
                out.append(
                    _mark_followup(
                        followup,
                        profile_name,
                        plain_payload_text=build_opt_upload_data_plaintext(
                            session_id=int(runtime_session_id),
                            upload_data_type=2,
                            specific_type=None,
                        ),
                    )
                )
                continue
            followup = _build_static_cipher_followup(
                cmd=cmd,
                payload_text=str(payload_text or ""),
                msg_id=int(runtime_msg_id) + offset,
                unk=0,
            )
            out.append(_mark_followup(followup, profile_name))

        if selected == "historical_full_dynamic_second582":
            plain_second_582 = build_opmonitor_media_plaintext(
                action="Start",
                channel=int(channel),
                stream_type=stream_type or "Main",
                trans_mode=trans_mode or "TCP",
                combine_mode=combine_mode or "CONNECT_ALL",
                session_id_mode="random32",
                include_channel=True,
                include_combine_mode=False,
                include_stream_type=False,
                include_trans_mode=False,
            )
            second_582 = build_6611_dataenc_followup(
                cmd=0x0582,
                plain_payload_text=plain_second_582,
                communicate_key=communicate_key,
                msg_type=0,
                session_id=int(runtime_session_id),
                msg_id=int(runtime_msg_id) + 128,
                unk=0,
            )
            out.append(
                _mark_followup(
                    second_582,
                    profile_name,
                    delay_before=0.5,
                    plain_payload_text=plain_second_582,
                )
            )
        else:
            second_582 = _build_static_cipher_followup(
                cmd=0x0582,
                payload_text="K1l/jqA3dF4cFhKTnv9bIutICdx+TL7cVXYDM4phZZUMoq2Wi4kYSLz+i25DcKkEFBrP35IJMpPwdsCSzunSvI7bKrv2GF9fXveGTjndNP5vYgH2VqmpfLC1P2f7naa4j/Fgu69YB5EvYPBt7d8BtTFL9mDPo4jEDLRMGhGIzVUhZT/oY9LZPsD/cPUK9hOkYYWq2t3eSHbpFECM5OkoEgg7Nsy3y7K5xqfO4hMZCps=",
                msg_id=int(runtime_msg_id) + 128,
                unk=0,
            )
            out.append(_mark_followup(second_582, profile_name, delay_before=0.5))

        late_64c = build_opt_upload_data_followup(
            session_id=int(runtime_session_id),
            msg_id=int(runtime_msg_id) + 136,
            communicate_key=communicate_key,
            upload_data_type=2,
            specific_type=None,
            stop=True,
            unk=0,
        )
        out.append(
            _mark_followup(
                late_64c,
                profile_name,
                delay_before=0.6,
                plain_payload_text=build_opt_upload_data_plaintext(
                    session_id=int(runtime_session_id),
                    upload_data_type=2,
                    specific_type=None,
                ),
            )
        )

    if selected in {
        "historical_order_built_queries_dynamic_second582",
        "historical_order_built_queries_dynamic_second582_nostop",
    }:
        profile_name = selected
        builder_schedule: list[dict[str, Any]] = []
        builder_schedule.append(
            _mark_followup(
                build_named_ptl_followup(
                    cmd=0x0550,
                    name="SystemFunction",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 16,
                    unk=0,
                ),
                profile_name,
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_opt_upload_data_followup(
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 24,
                    communicate_key=communicate_key,
                    upload_data_type=2,
                    specific_type=None,
                    stop=False,
                    unk=0,
                ),
                profile_name,
                plain_payload_text=build_opt_upload_data_plaintext(
                    session_id=int(runtime_session_id),
                    upload_data_type=2,
                    specific_type=None,
                ),
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_named_ptl_followup(
                    cmd=0x03FC,
                    name="SystemInfo",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 32,
                    unk=0,
                ),
                profile_name,
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_named_ptl_followup(
                    cmd=0x0550,
                    name="SystemFunction",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 40,
                    unk=0,
                ),
                profile_name,
            )
        )
        for offset in (48, 56, 64, 72, 80):
            builder_schedule.append(
                _mark_followup(
                    build_named_ptl_followup(
                        cmd=0x0412,
                        name="fVideo.AudioSupportType",
                        communicate_key=communicate_key,
                        session_id=int(runtime_session_id),
                        msg_id=int(runtime_msg_id) + offset,
                        unk=0,
                    ),
                    profile_name,
                )
            )
        builder_schedule.append(
            _mark_followup(
                build_named_ptl_followup(
                    cmd=0x0550,
                    name="SystemFunction",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 88,
                    unk=0,
                ),
                profile_name,
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_opt_upload_data_followup(
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 96,
                    communicate_key=communicate_key,
                    upload_data_type=2,
                    specific_type=None,
                    stop=False,
                    unk=0,
                ),
                profile_name,
                plain_payload_text=build_opt_upload_data_plaintext(
                    session_id=int(runtime_session_id),
                    upload_data_type=2,
                    specific_type=None,
                ),
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_named_ptl_followup(
                    cmd=0x03FC,
                    name="SystemInfo",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 104,
                    unk=0,
                ),
                profile_name,
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_opt_upload_data_followup(
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 112,
                    communicate_key=communicate_key,
                    upload_data_type=2,
                    specific_type=None,
                    stop=True,
                    unk=0,
                ),
                profile_name,
                plain_payload_text=build_opt_upload_data_plaintext(
                    session_id=int(runtime_session_id),
                    upload_data_type=2,
                    specific_type=None,
                ),
            )
        )
        plain_second_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=stream_type or "Main",
            trans_mode=trans_mode or "TCP",
            combine_mode=combine_mode or "CONNECT_ALL",
            session_id_mode="random32",
            include_channel=True,
            include_combine_mode=False,
            include_stream_type=False,
            include_trans_mode=False,
        )
        builder_schedule.append(
            _mark_followup(
                build_6611_dataenc_followup(
                    cmd=0x0582,
                    plain_payload_text=plain_second_582,
                    communicate_key=communicate_key,
                    msg_type=0,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 128,
                    unk=0,
                ),
                profile_name,
                delay_before=0.5,
                plain_payload_text=plain_second_582,
            )
        )
        if selected == "historical_order_built_queries_dynamic_second582":
            builder_schedule.append(
                _mark_followup(
                    build_opt_upload_data_followup(
                        session_id=int(runtime_session_id),
                        msg_id=int(runtime_msg_id) + 136,
                        communicate_key=communicate_key,
                        upload_data_type=2,
                        specific_type=None,
                        stop=True,
                        unk=0,
                    ),
                    profile_name,
                    delay_before=0.6,
                    plain_payload_text=build_opt_upload_data_plaintext(
                        session_id=int(runtime_session_id),
                        upload_data_type=2,
                        specific_type=None,
                    ),
                )
            )
        out.extend(builder_schedule)

    if selected == "app_reference_first_6611":
        profile_name = selected
        builder_schedule: list[dict[str, Any]] = []
        session_hex = _format_session_hex(int(runtime_session_id), width=10)
        app_vekey1 = _get_appref_vekey1_override() or _normalize_media_random_str(vekey1) or _generate_ascii_key(64)
        device_uuid = str(device_id or "").strip()
        monitor_stream_type = str(stream_type or "Main")
        monitor_combine_mode = "CONNECT_ALL" if monitor_stream_type.strip().lower() == "main" else "NONE"

        for offset, name, delay_before, burst_group in (
            (0, "fVideo.AudioSupportType", 0.48, None),
            (8, "Detect.MotionDetect.[0]", 0.629, None),
            (24, "Uart.PTZControlCmd", 1.25, "appref_after_pkt6_cluster_b"),
            (32, "Ptz.GunBallLocate", 0.0, "appref_after_pkt6_cluster_b"),
        ):
            builder_schedule.append(
                _mark_followup(
                    build_named_session_followup(
                        cmd=0x0412,
                        name=name,
                        communicate_key=communicate_key,
                        session_id=int(runtime_session_id),
                        msg_id=int(runtime_msg_id) + offset,
                        unk=0,
                    ),
                    profile_name,
                    delay_before=delay_before,
                    burst_group=burst_group,
                )
            )
        plain_first_582 = build_opmonitor_media_plaintext(
            action="Start",
            channel=int(channel),
            stream_type=monitor_stream_type,
            trans_mode="TCP",
            combine_mode=monitor_combine_mode,
            session_hex=session_hex,
            session_id_mode="hex",
            extra_parameters={"VEKEY1": app_vekey1},
            include_channel=True,
            include_combine_mode=True,
            include_stream_type=True,
            include_trans_mode=True,
        )
        builder_schedule.append(
            _mark_followup(
                build_6611_dataenc_followup(
                    cmd=0x0582,
                    plain_payload_text=plain_first_582,
                    communicate_key=communicate_key,
                    msg_type=0,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 40,
                    unk=0,
                ),
                profile_name,
                delay_before=0.75,
                plain_payload_text=plain_first_582,
                burst_group=None,
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_named_session_followup(
                    cmd=0x0550,
                    name="FishEyePlatform",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 48,
                    unk=0,
                    session_id_text="0x01",
                    session_first=True,
                ),
                profile_name,
                delay_before=0.541,
                burst_group=None,
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_opt_upload_data_followup(
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 56,
                    communicate_key=communicate_key,
                    upload_data_type=8,
                    specific_type="wifi/elect",
                    stop=False,
                    unk=0,
                ),
                profile_name,
                delay_before=0.45,
                plain_payload_text=build_opt_upload_data_plaintext(
                    session_id=int(runtime_session_id),
                    upload_data_type=8,
                    specific_type="wifi/elect",
                ),
                burst_group="appref_post582_cluster_c1",
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_named_session_followup(
                    cmd=0x03FC,
                    name="WifiRouteInfo",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 64,
                    unk=0,
                ),
                profile_name,
                burst_group="appref_post582_cluster_c1",
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_named_session_followup(
                    cmd=0x0550,
                    name="DecoderPram",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 72,
                    unk=0,
                ),
                profile_name,
                delay_before=0.094,
                burst_group=None,
            )
        )
        for offset, name, delay_before, burst_group in (
            (80, "Ptz.GunBallLocate", 0.001, None),
            (88, "Ptz.GunBallLocate", 0.057, None),
            (96, "General.AppBindFlag", 0.669, None),
        ):
            builder_schedule.append(
                _mark_followup(
                    build_named_session_followup(
                        cmd=0x0412,
                        name=name,
                        communicate_key=communicate_key,
                        session_id=int(runtime_session_id),
                        msg_id=int(runtime_msg_id) + offset,
                        unk=0,
                    ),
                    profile_name,
                    delay_before=delay_before,
                    burst_group=burst_group,
                )
            )
        builder_schedule.append(
            _mark_followup(
                build_opt_upload_data_followup(
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 104,
                    communicate_key=communicate_key,
                    upload_data_type=8,
                    specific_type="wifi/elect",
                    stop=False,
                    unk=0,
                ),
                profile_name,
                delay_before=0.144,
                plain_payload_text=build_opt_upload_data_plaintext(
                    session_id=int(runtime_session_id),
                    upload_data_type=8,
                    specific_type="wifi/elect",
                ),
                burst_group="appref_post582_cluster_d1",
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_named_session_followup(
                    cmd=0x0550,
                    name="GoToPosition",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 112,
                    unk=0,
                ),
                profile_name,
                burst_group="appref_post582_cluster_d1",
            )
        )
        for offset, delay_before, burst_group in (
            (120, 0.233, None),
            (128, 0.298, None),
        ):
            builder_schedule.append(
                _mark_followup(
                    build_opt_upload_data_followup(
                        session_id=int(runtime_session_id),
                        msg_id=int(runtime_msg_id) + offset,
                        communicate_key=communicate_key,
                        upload_data_type=8,
                        specific_type="wifi/elect",
                        stop=False,
                        unk=0,
                    ),
                    profile_name,
                    delay_before=delay_before,
                    plain_payload_text=build_opt_upload_data_plaintext(
                        session_id=int(runtime_session_id),
                        upload_data_type=8,
                        specific_type="wifi/elect",
                    ),
                    burst_group=burst_group,
                )
            )
        opversionreq_plain = build_named_session_plaintext(
            "OPVersionReq",
            session_id=int(runtime_session_id),
            payload_body={
                "Expect": 0,
                "Language": "English",
                "Manual": 1,
                "UUID": device_uuid,
                "DevID": "000A07F3100103467320000000",
                "CurVersion": "2025-09-06",
                "DevType": 2,
            },
        )
        builder_schedule.append(
            _mark_followup(
                build_6611_dataenc_followup(
                    cmd=0x07E0,
                    plain_payload_text=opversionreq_plain,
                    communicate_key=communicate_key,
                    msg_type=0,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 136,
                    unk=0,
                ),
                profile_name,
                plain_payload_text=opversionreq_plain,
                delay_before=0.336,
                burst_group=None,
            )
        )
        keepalive_plain = build_named_session_plaintext(
            "KeepAlive",
            session_id=int(runtime_session_id),
        )
        builder_schedule.append(
            _mark_followup(
                build_6611_dataenc_followup(
                    cmd=0x03EE,
                    plain_payload_text=keepalive_plain,
                    communicate_key=communicate_key,
                    msg_type=0,
                    session_id=int(runtime_session_id),
                    msg_id=0,
                    unk=0,
                ),
                profile_name,
                delay_before=5.692,
                plain_payload_text=keepalive_plain,
                burst_group=None,
            )
        )
        builder_schedule.append(
            _mark_followup(
                build_named_session_followup(
                    cmd=0x03FC,
                    name="WifiRouteInfo",
                    communicate_key=communicate_key,
                    session_id=int(runtime_session_id),
                    msg_id=int(runtime_msg_id) + 144,
                    unk=0,
                ),
                profile_name,
                delay_before=6.469,
                burst_group=None,
            )
        )
        if str(os.environ.get("ICSEE_APPREF_SEND_TEARDOWN") or "").strip() == "1":
            builder_schedule.append(
                _mark_followup(
                    build_opt_upload_data_followup(
                        session_id=int(runtime_session_id),
                        msg_id=int(runtime_msg_id) + 152,
                        communicate_key=communicate_key,
                        upload_data_type=8,
                        specific_type="wifi/elect",
                        stop=True,
                        unk=0,
                    ),
                    profile_name,
                    delay_before=5.626,
                    plain_payload_text=build_opt_upload_data_plaintext(
                        session_id=int(runtime_session_id),
                        upload_data_type=8,
                        specific_type="wifi/elect",
                    ),
                    burst_group=None,
                )
            )
            plain_second_582 = build_opmonitor_media_plaintext(
                action="Stop",
                channel=int(channel),
                stream_type=monitor_stream_type,
                trans_mode="TCP",
                combine_mode=monitor_combine_mode,
                session_hex=session_hex,
                session_id_mode="hex",
                include_channel=True,
                include_combine_mode=True,
                include_stream_type=True,
                include_trans_mode=True,
            )
            builder_schedule.append(
                _mark_followup(
                    build_6611_dataenc_followup(
                        cmd=0x0582,
                        plain_payload_text=plain_second_582,
                        communicate_key=communicate_key,
                        msg_type=0,
                        session_id=int(runtime_session_id),
                        msg_id=int(runtime_msg_id) + 160,
                        unk=0,
                    ),
                    profile_name,
                    delay_before=0.705,
                    burst_group=None,
                    plain_payload_text=plain_second_582,
                )
            )
            builder_schedule.append(
                _mark_followup(
                    build_opt_upload_data_followup(
                        session_id=int(runtime_session_id),
                        msg_id=int(runtime_msg_id) + 168,
                        communicate_key=communicate_key,
                        upload_data_type=8,
                        specific_type="wifi/elect",
                        stop=True,
                        unk=0,
                    ),
                    profile_name,
                    delay_before=0.013,
                    burst_group=None,
                    plain_payload_text=build_opt_upload_data_plaintext(
                        session_id=int(runtime_session_id),
                        upload_data_type=8,
                        specific_type="wifi/elect",
                    ),
                )
            )
        out.extend(builder_schedule)

    return out


class CloudLiveExtractor:
    def __init__(self, boss_bases: list[str] | None = None, openapi_bases: list[str] | None = None) -> None:
        self.boss_bases = boss_bases or list(DEFAULT_BOSS_BASES)
        self.openapi_bases = openapi_bases or list(DEFAULT_OPENAPI_BASES)
        self._last_login_kwargs: dict[str, Any] = {}

    def _apply_hints_to_session(self, session: CloudAuthSession, hints: _AuthHints) -> None:
        if hints.app_keys and not session.app_key:
            session.app_key = hints.app_keys[0]
        if hints.vendors and not session.vendor:
            session.vendor = hints.vendors[0]
        if hints.uuids and not session.uuid:
            session.uuid = hints.uuids[0]
        if hints.move_cards and not session.move_card:
            session.move_card = hints.move_cards[0]
        if hints.secrets and not session.secret:
            session.secret = hints.secrets[0]
        if hints.muserids and not session.dev_muserid:
            session.dev_muserid = hints.muserids[0]
        if hints.public_keys and not session.public_key:
            session.public_key = hints.public_keys[0]
        if hints.vms_keys and not session.vms_key:
            session.vms_key = hints.vms_keys[0]

    def _ensure_vms_key(self, session: CloudAuthSession) -> None:
        if session.vms_key:
            try:
                decoded = base64.b64decode(session.vms_key)
                if len(decoded) in (16, 24, 32):
                    return
            except Exception:
                pass
        session.vms_key = _generate_vms_key()

    def _build_encrypted_boss_request(
        self,
        session: CloudAuthSession,
        params: dict[str, Any],
    ) -> tuple[dict[str, str], dict[str, Any]] | None:
        if not _crypto_ready():
            return None
        if not session.user_token or not session.public_key:
            return None
        self._ensure_vms_key(session)
        encrypted_key = _encrypt_rsa_key(session.vms_key, session.public_key)
        encrypted_req = _encrypt_aes_req(params, session.vms_key)
        if not encrypted_key or not encrypted_req:
            return None
        headers = {
            "Content-Type": "application/json",
            "Authorization": session.user_token,
            "Key": encrypted_key,
        }
        return headers, {"req": encrypted_req}

    def _apply_hints_from_boss_result(self, session: CloudAuthSession, result: HttpResult) -> None:
        source = result.json_data if result.json_data is not None else result.text
        hints = _extract_auth_hints(source)
        self._apply_hints_to_session(session, hints)
        if isinstance(result.json_data, dict):
            encrypted_data = result.json_data.get("data")
            if isinstance(encrypted_data, str) and encrypted_data and session.vms_key:
                decrypted = _decrypt_aes_data(encrypted_data, session.vms_key)
                if decrypted is not None:
                    decrypted_hints = _extract_auth_hints(decrypted)
                    self._apply_hints_to_session(session, decrypted_hints)

    def fetch_app_detail(self, session: CloudAuthSession, timeout: int = 20) -> tuple[CloudAuthSession, list[HttpResult]]:
        attempts: list[HttpResult] = []
        if not session.app_key:
            return session, attempts
        encrypted_retries = 3
        payloads = [
            {
                "appKey": session.app_key,
                "pkg": "com.xm.csee",
                "appVer": "7.7.7",
                "versionCode": "77703",
                "lang": "ru",
                "operateTag": "A",
            },
            {
                "appKey": session.app_key,
                "pkg": "com.xm.csee",
                "appVer": "7.7.7",
                "versionCode": "77730",
                "lang": "ru",
                "operateTag": "A",
            },
            {
                "appKey": session.app_key,
                "pkg": "com.xm.csee",
                "appVer": "7.7.7",
                "versionCode": "77703",
            },
            {"appKey": session.app_key, "pkg": "com.xm.csee"},
            {"appKey": session.app_key},
            {"appKey": session.app_key, "authorization": session.user_token},
            {},
        ]
        found_openapi_parts = bool(session.uuid and session.move_card and session.secret)
        base_candidates = [b for b in [session.boss_base, *self.boss_bases] if b]
        for base in _dedupe(base_candidates):
            url = f"{base.rstrip('/')}/appKey/appDetail"
            for payload in payloads:
                encrypted = self._build_encrypted_boss_request(session=session, params=payload)
                if encrypted is not None:
                    headers, body = encrypted
                    for _ in range(encrypted_retries):
                        result = http_json(url=url, method="POST", payload=body, headers=headers, timeout=timeout)
                        attempts.append(result)
                        self._apply_hints_from_boss_result(session, result)
                        if _is_success(result) and session.uuid and session.move_card and session.secret:
                            return session, attempts
                        if _is_success(result):
                            found_openapi_parts = bool(session.uuid and session.move_card and session.secret) or found_openapi_parts
                    # Keep appDetail in encrypted mode only once available.
                    # Mixed encrypted/plain attempts can invalidate the server-side key context.
                    continue
                # Plain fallback path for environments without crypto libs.
                plain_headers = {"Content-Type": "application/json"}
                if session.user_token:
                    plain_headers["Authorization"] = session.user_token
                plain = http_json(url=url, method="POST", payload={"request": payload}, headers=plain_headers, timeout=timeout)
                attempts.append(plain)
                self._apply_hints_from_boss_result(session, plain)
                if _is_success(plain) and session.uuid and session.move_card and session.secret:
                    return session, attempts
                if _is_success(plain):
                    found_openapi_parts = bool(session.uuid and session.move_card and session.secret) or found_openapi_parts
            if found_openapi_parts:
                return session, attempts
        return session, attempts

    def _build_login_payloads(self, account: str, password: str, app_key: str = "", iso_code: str = "") -> list[dict[str, Any]]:
        base = BossApi.guess_login_payloads(account=account, password=password, app_key=app_key, iso_code=iso_code)
        extras = [
            {"account": account, "password": password, "appKey": app_key} if app_key else {"account": account, "password": password},
            {"userName": account, "password": password, "appKey": app_key} if app_key else {"userName": account, "password": password},
        ]
        output: list[dict[str, Any]] = []
        seen: set[str] = set()
        for payload in base + extras:
            cleaned = {k: v for k, v in payload.items() if v not in ("", None)}
            key = json.dumps(cleaned, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            output.append(cleaned)
        return output

    def _session_from_hints(self, account: str, token: str, hints: _AuthHints, app_key_hint: str, raw_login: Any) -> CloudAuthSession:
        jwt_payload = _decode_jwt_payload(token)
        app_key = app_key_hint or (hints.app_keys[0] if hints.app_keys else "") or str(jwt_payload.get("appKey") or "")
        move_card = hints.move_cards[0] if hints.move_cards else 0
        return CloudAuthSession(
            account=account,
            user_token=token,
            token_expires_utc=_jwt_expiry_utc(token),
            app_key=app_key,
            vendor=hints.vendors[0] if hints.vendors else "",
            uuid=hints.uuids[0] if hints.uuids else "",
            move_card=move_card,
            secret=hints.secrets[0] if hints.secrets else "",
            dev_muserid=hints.muserids[0] if hints.muserids else "",
            public_key=hints.public_keys[0] if hints.public_keys else "",
            vms_key=hints.vms_keys[0] if hints.vms_keys else "",
            raw_login=raw_login if isinstance(raw_login, dict) else {"raw": str(raw_login)[:2000]},
        )

    def login_with_ams_credentials(
        self,
        account: str,
        password: str,
        *,
        app_key: str,
        uuid: str,
        secret: str,
        move_card: int,
        vendor: str = "",
        iso_code: str = "",
        timeout: int = 20,
        ams_bases: list[str] | None = None,
        user_agent: str = DEFAULT_AMS_USER_AGENT,
        ssl_verify: bool = True,
    ) -> tuple[CloudAuthSession, list[HttpResult]]:
        resolved_account = str(account or "").strip()
        resolved_password = str(password or "")
        resolved_app_key = str(app_key or "").strip()
        resolved_uuid = str(uuid or "").strip()
        resolved_secret = str(secret or "").strip()
        resolved_vendor = str(vendor or "").strip()
        resolved_iso = str(iso_code or "").strip()
        resolved_move_card = int(move_card or 0)
        if not resolved_account or not resolved_password:
            raise RuntimeError("account/password are required for AMS loginExist")
        missing = [
            name
            for name, value in (
                ("app_key", resolved_app_key),
                ("uuid", resolved_uuid),
                ("secret", resolved_secret),
                ("move_card", resolved_move_card),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(f"AMS loginExist preauth config missing: {', '.join(missing)}")
        self._last_login_kwargs = {
            "mode": "ams_password",
            "account": resolved_account,
            "password": resolved_password,
            "app_key": resolved_app_key,
            "uuid": resolved_uuid,
            "secret": resolved_secret,
            "move_card": resolved_move_card,
            "vendor": resolved_vendor,
            "iso_code": resolved_iso,
            "timeout": timeout,
            "ssl_verify": ssl_verify,
        }
        attempts: list[HttpResult] = []
        bases = _dedupe([*(ams_bases or []), *DEFAULT_AMS_BASES])
        for base in bases:
            req_time = _next_ams_time_millis()
            signature = compute_signature(
                uuid=resolved_uuid,
                app_key=resolved_app_key,
                secret=resolved_secret,
                time_millis=req_time,
                move_card=resolved_move_card,
            )
            aes_key = _derive_ams_response_key(req_time, resolved_secret)
            body_values = {"account": resolved_account, "pass": resolved_password}
            if resolved_iso:
                body_values["isoCode"] = resolved_iso
            plain_body = urllib.parse.urlencode(body_values)
            encrypted_body = _encrypt_ams_hex_payload(plain_body, aes_key)
            url = f"{base.rstrip('/')}/loginExist/v3/{req_time}/{signature}.rs"
            headers = {
                "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
                "Accept-Charset": "utf-8",
                "Accept-Encoding": "gzip, deflate",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent,
                "appKey": resolved_app_key,
                "uuid": resolved_uuid,
            }
            result = http_text(
                url=url,
                method="POST",
                payload=encrypted_body,
                headers=headers,
                timeout=timeout,
                ssl_verify=ssl_verify,
            )
            result.request_payload = {
                "time_millis": req_time,
                "signature": signature,
                "user_agent": user_agent,
                "uuid": resolved_uuid,
                "app_key": resolved_app_key,
                "move_card": resolved_move_card,
                "plain_body": plain_body,
                "encrypted_body": encrypted_body,
            }
            attempts.append(result)
            if not result.ok or not result.text:
                continue
            try:
                plain_text = _decrypt_ams_hex_payload(result.text, aes_key)
                plain_json = json.loads(plain_text)
            except Exception as exc:  # noqa: BLE001
                result.error = f"loginexist_decrypt:{exc}"
                continue
            result.json_data = plain_json
            result.text = plain_text
            data = plain_json.get("data") if isinstance(plain_json, dict) and isinstance(plain_json.get("data"), dict) else {}
            access_token = str(data.get("accessToken") or plain_json.get("accessToken") or "").strip()
            refresh_token = str(data.get("refreshToken") or plain_json.get("refreshToken") or "").strip()
            if not access_token:
                continue
            hints = _extract_auth_hints(plain_json)
            session = self._session_from_hints(
                account=resolved_account,
                token=access_token,
                hints=hints,
                app_key_hint=resolved_app_key,
                raw_login=plain_json,
            )
            session.refresh_token = refresh_token
            session.uuid = session.uuid or resolved_uuid
            session.secret = session.secret or resolved_secret
            session.move_card = session.move_card or resolved_move_card
            session.vendor = session.vendor or resolved_vendor
            return session, attempts
        raise RuntimeError(f"AMS loginExist failed; attempts={_summarize_http_results(attempts, limit=8)}")

    def login(
        self,
        account: str,
        password: str,
        app_key: str = "",
        iso_code: str = "",
        timeout: int = 20,
    ) -> tuple[CloudAuthSession, list[HttpResult]]:
        self._last_login_kwargs = {
            "mode": "password",
            "account": account,
            "password": password,
            "app_key": app_key,
            "iso_code": iso_code,
            "timeout": timeout,
        }
        attempts: list[HttpResult] = []
        fallback: CloudAuthSession | None = None
        auth_required_hits = 0
        payloads = self._build_login_payloads(account=account, password=password, app_key=app_key, iso_code=iso_code)
        for base in self.boss_bases:
            url = f"{base.rstrip('/')}{LOGIN_PATH}"
            for payload in payloads:
                for body in ({"request": payload}, payload):
                    result = http_json(url=url, method="POST", payload=body, timeout=timeout)
                    attempts.append(result)
                    code, msg = _extract_code_and_msg(result.json_data)
                    msg_l = msg.lower()
                    if code == "-91002" and "authorization" in msg_l and "appkey" in msg_l:
                        auth_required_hits += 1
                        if auth_required_hits >= 3 and not app_key:
                            raise RuntimeError(
                                "Login endpoint requires existing authorization token + appKey; "
                                "direct login/password flow is not accepted by this endpoint. "
                                "Use access-token flow instead. "
                                f"attempts={_summarize_http_results(attempts, limit=6)}"
                            )
                    hints = _extract_auth_hints(result.json_data if result.json_data is not None else result.text)
                    token = _pick_best_token(hints.user_tokens)
                    if not token:
                        continue
                    session = self._session_from_hints(
                        account=account,
                        token=token,
                        hints=hints,
                        app_key_hint=app_key,
                        raw_login=result.json_data if result.json_data is not None else result.text,
                    )
                    session.boss_base = base.rstrip("/")
                    if _is_success(result):
                        return session, attempts
                    if fallback is None:
                        fallback = session
        if fallback is not None:
            return fallback, attempts
        raise RuntimeError(f"Login failed; attempts={_summarize_http_results(attempts, limit=8)}")

    def login_with_authorization(
        self,
        access_token: str,
        app_key: str = "",
        timeout: int = 20,
    ) -> tuple[CloudAuthSession, list[HttpResult]]:
        token = access_token.strip()
        if not token:
            raise RuntimeError("access_token is empty")
        token_app_key = str(_decode_jwt_payload(token).get("appKey") or "")
        resolved_app_key = app_key or token_app_key
        if not resolved_app_key:
            raise RuntimeError("app_key is required for access-token login mode")

        self._last_login_kwargs = {
            "mode": "access_token",
            "access_token": token,
            "app_key": resolved_app_key,
            "timeout": timeout,
        }
        payloads = [
            {"authorization": token, "appKey": resolved_app_key},
            {"authorization": token, "appKey": resolved_app_key, "lang": "ru"},
            {"authorization": token, "appKey": resolved_app_key, "appVer": "7.7.7"},
        ]
        attempts: list[HttpResult] = []
        fallback: CloudAuthSession | None = None
        fatal_hint_hits = 0
        for base in self.boss_bases:
            url = f"{base.rstrip('/')}{LOGIN_PATH}"
            for payload in payloads:
                # H5 path is type=1 -> {"request": payload}.
                for body in ({"request": payload},):
                    result = http_json(url=url, method="POST", payload=body, timeout=timeout)
                    attempts.append(result)
                    hints = _extract_auth_hints(result.json_data if result.json_data is not None else result.text)
                    session_token = _pick_best_token(hints.user_tokens) or token
                    session = self._session_from_hints(
                        account="token-auth",
                        token=session_token,
                        hints=hints,
                        app_key_hint=resolved_app_key,
                        raw_login=result.json_data if result.json_data is not None else result.text,
                    )
                    session.boss_base = base.rstrip("/")
                    if _is_success(result):
                        return session, attempts
                    code, msg = _extract_code_and_msg(result.json_data)
                    msg_l = msg.lower()
                    if code == "-83000":
                        fatal_hint_hits += 1
                        if fatal_hint_hits >= 3:
                            return session, attempts
                    if code in {"-91002", "4003", "4004"} and ("authorization" in msg_l or "token" in msg_l):
                        fatal_hint_hits += 1
                        if fatal_hint_hits >= 4:
                            return session, attempts
                    if fallback is None:
                        fallback = session
        if fallback is not None:
            return fallback, attempts
        raise RuntimeError(f"Authorization login failed; attempts={_summarize_http_results(attempts, limit=8)}")

    def refresh_session(self, timeout: int = 20) -> tuple[CloudAuthSession, list[HttpResult]]:
        if not self._last_login_kwargs:
            raise RuntimeError("No previous login context for refresh")
        kwargs = dict(self._last_login_kwargs)
        kwargs["timeout"] = timeout
        mode = kwargs.pop("mode", "password")
        if mode == "access_token":
            return self.login_with_authorization(**kwargs)
        if mode == "ams_password":
            return self.login_with_ams_credentials(**kwargs)
        return self.login(**kwargs)

    def exchange_device_token(
        self,
        session: CloudAuthSession,
        device_id: str,
        channel: int = 0,
        timeout: int = 20,
    ) -> tuple[CloudAuthSession, list[HttpResult]]:
        attempts: list[HttpResult] = []
        payloads = [
            {"sn": device_id},
            {"deviceId": device_id},
            {"devId": device_id},
            {"sn": device_id, "channel": channel},
            {"deviceId": device_id, "channel": channel},
        ]
        header_variants: list[dict[str, str]] = [{"Authorization": session.user_token}, {}]
        base_candidates = [b for b in [session.boss_base, *self.boss_bases] if b]
        for base in _dedupe(base_candidates):
            url = f"{base.rstrip('/')}{DEVICE_TOKEN_PATH}"
            for payload in payloads:
                encrypted = self._build_encrypted_boss_request(session=session, params=payload)
                if encrypted is not None:
                    enc_headers, enc_body = encrypted
                    enc_result = http_json(
                        url=url,
                        method="POST",
                        payload=enc_body,
                        headers=enc_headers,
                        timeout=timeout,
                    )
                    attempts.append(enc_result)
                    enc_hints = _extract_auth_hints(enc_result.json_data if enc_result.json_data is not None else enc_result.text)
                    self._apply_hints_to_session(session, enc_hints)
                    enc_token = _pick_best_token(enc_hints.device_tokens)
                    if (
                        not enc_token
                        and isinstance(enc_result.json_data, dict)
                        and "token" in enc_result.json_data
                    ):
                        enc_token = _pick_best_token(enc_hints.user_tokens)
                    if enc_token:
                        session.device_token = enc_token
                        session.raw_device_token = (
                            enc_result.json_data if isinstance(enc_result.json_data, dict) else {"raw": enc_result.text[:2000]}
                        )
                        return session, attempts
                    # Encrypted path is available; avoid expensive plain brute-force here.
                    continue

                for body in ({"request": payload}, payload):
                    for headers in header_variants:
                        merged_headers = {"Content-Type": "application/json"}
                        merged_headers.update(headers)
                        result = http_json(url=url, method="POST", payload=body, headers=merged_headers, timeout=timeout)
                        attempts.append(result)
                        hints = _extract_auth_hints(result.json_data if result.json_data is not None else result.text)
                        self._apply_hints_to_session(session, hints)
                        token = _pick_best_token(hints.device_tokens)
                        if not token and isinstance(result.json_data, dict) and "token" in result.json_data:
                            token = _pick_best_token(hints.user_tokens)
                        if token:
                            session.device_token = token
                            session.raw_device_token = (
                                result.json_data if isinstance(result.json_data, dict) else {"raw": result.text[:2000]}
                            )
                            return session, attempts
        return session, attempts

    def fetch_jvss_device_login_token(
        self,
        session: CloudAuthSession,
        device_id: str,
        *,
        timeout: int = 20,
        is_latest: bool = True,
        jvss_bases: list[str] | None = None,
        ssl_verify: bool = True,
    ) -> tuple[CloudAuthSession, list[HttpResult]]:
        attempts: list[HttpResult] = []
        serial = str(device_id or "").strip()
        if not serial:
            raise RuntimeError("device_id is required for JVSS token refresh")
        if not session.user_token:
            raise RuntimeError("user_token is required for JVSS token refresh")
        if not session.uuid or not session.app_key:
            raise RuntimeError("uuid/app_key are required for JVSS token refresh")
        payload = {
            "deviceNo": serial,
            "isLatest": bool(is_latest),
        }
        headers = {
            "Authorization": session.user_token,
            "uuid": session.uuid,
            "appKey": session.app_key,
            "Connection": "close",
            "Content-Type": "application/json",
        }
        bases = _dedupe([*(jvss_bases or []), *DEFAULT_JVSS_BASES])
        for base in bases:
            url = urllib.parse.urljoin(base.rstrip("/") + "/", JVSS_DEVICE_TOKEN_PATH.lstrip("/"))
            result = http_json(url=url, method="POST", payload=payload, headers=headers, timeout=timeout, ssl_verify=ssl_verify)
            attempts.append(result)
            token = _extract_admin_token_from_payload(result.json_data if result.json_data is not None else result.text)
            if token:
                session.device_token = token
                session.raw_device_token = (
                    result.json_data if isinstance(result.json_data, dict) else {"raw": result.text[:2000]}
                )
                return session, attempts
        return session, attempts

    def fetch_ams_device_list(
        self,
        session: CloudAuthSession,
        *,
        timeout: int = 20,
        ams_bases: list[str] | None = None,
        user_agent: str = DEFAULT_AMS_USER_AGENT,
        time_millis: str = "",
        ssl_verify: bool = True,
    ) -> tuple[CloudAuthSession, list[dict[str, Any]], list[HttpResult]]:
        attempts: list[HttpResult] = []
        if not session.user_token:
            raise RuntimeError("user_token is required for AMS device list")
        if not session.app_key or not session.uuid or not session.secret or not session.move_card:
            raise RuntimeError("app_key/uuid/secret/move_card are required for AMS device list")

        bases = _dedupe([*(ams_bases or []), *DEFAULT_AMS_BASES])
        for base in bases:
            req_time = str(time_millis or _next_ams_time_millis()).strip()
            signature = compute_signature(
                uuid=session.uuid,
                app_key=session.app_key,
                secret=session.secret,
                time_millis=req_time,
                move_card=int(session.move_card),
            )
            url = f"{base.rstrip('/')}/msdlistCode/v3/{req_time}/{signature}.rs"
            headers = {
                "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
                "Accept-Charset": "utf-8",
                "Accept-Encoding": "gzip, deflate",
                "Authorization": session.user_token,
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent,
                "appKey": session.app_key,
                "uuid": session.uuid,
            }
            result = http_text(
                url=url,
                method="POST",
                payload=b"",
                headers=headers,
                timeout=timeout,
                ssl_verify=ssl_verify,
            )
            result.request_payload = {
                "time_millis": req_time,
                "signature": signature,
                "user_agent": user_agent,
                "uuid": session.uuid,
                "app_key": session.app_key,
            }
            attempts.append(result)
            if not result.ok or not result.text:
                continue
            try:
                aes_key = _derive_ams_response_key(req_time, session.secret)
                plain_text = _decrypt_ams_hex_payload(result.text, aes_key)
                plain_json = json.loads(plain_text)
            except Exception as exc:  # noqa: BLE001
                result.error = f"ams_decrypt:{exc}"
                continue
            result.json_data = plain_json
            result.text = plain_text
            devices = _extract_ams_devices(plain_json)
            if devices:
                session.raw_ams_device_list = {
                    "base": base,
                    "time_millis": req_time,
                    "signature": signature,
                    "devices": devices,
                    "raw": plain_json,
                }
                return session, devices, attempts
        return session, [], attempts

    def fetch_acapp_auth_list(
        self,
        session: CloudAuthSession,
        *,
        serial_number: str,
        auth_type: str = "rps",
        timeout: int = 20,
        ams_bases: list[str] | None = None,
        user_agent: str = DEFAULT_AMS_USER_AGENT,
        time_millis: str = "",
        ssl_verify: bool = True,
    ) -> tuple[CloudAuthSession, list[dict[str, Any]], list[HttpResult]]:
        attempts: list[HttpResult] = []
        if not serial_number:
            raise RuntimeError("serial_number is required for acapp auth list")
        if not session.user_token:
            raise RuntimeError("user_token is required for acapp auth list")
        if not session.app_key or not session.uuid or not session.secret or not session.move_card:
            raise RuntimeError("app_key/uuid/secret/move_card are required for acapp auth list")

        bases = _dedupe([*(ams_bases or []), *DEFAULT_AMS_BASES])
        for base in bases:
            req_time = str(time_millis or _next_ams_time_millis()).strip()
            signature = compute_signature(
                uuid=session.uuid,
                app_key=session.app_key,
                secret=session.secret,
                time_millis=req_time,
                move_card=int(session.move_card),
            )
            aes_key = _derive_ams_response_key(req_time, session.secret)
            plain_body = urllib.parse.urlencode({"uuid": serial_number, "type": auth_type})
            encrypted_body = _encrypt_ams_hex_payload(plain_body, aes_key)
            url = f"{base.rstrip('/')}/acapp/v3/{req_time}/{signature}.rs"
            headers = {
                "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
                "Accept-Charset": "utf-8",
                "Accept-Encoding": "gzip, deflate",
                "Authorization": session.user_token,
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent,
                "appKey": session.app_key,
                "uuid": session.uuid,
            }
            result = http_text(
                url=url,
                method="POST",
                payload=encrypted_body,
                headers=headers,
                timeout=timeout,
                ssl_verify=ssl_verify,
            )
            result.request_payload = {
                "time_millis": req_time,
                "signature": signature,
                "user_agent": user_agent,
                "uuid": session.uuid,
                "app_key": session.app_key,
                "serial_number": serial_number,
                "auth_type": auth_type,
                "plain_body": plain_body,
                "encrypted_body": encrypted_body,
            }
            attempts.append(result)
            if not result.ok or not result.text:
                continue
            try:
                plain_text = _decrypt_ams_hex_payload(result.text, aes_key)
                plain_json = json.loads(plain_text)
            except Exception as exc:  # noqa: BLE001
                result.error = f"acapp_decrypt:{exc}"
                continue
            result.json_data = plain_json
            result.text = plain_text
            rows = _extract_acapp_auth_rows(plain_json)
            if rows:
                session.raw_acapp_auth_list = {
                    "base": base,
                    "time_millis": req_time,
                    "signature": signature,
                    "auth_type": auth_type,
                    "rows": rows,
                    "raw": plain_json,
                }
                return session, rows, attempts
        return session, [], attempts

    def _build_openapi_creds(
        self,
        session: CloudAuthSession,
        overrides: dict[str, Any] | None = None,
    ) -> tuple[OpenApiCreds | None, list[str]]:
        data = overrides or {}
        token_app_key = str(_decode_jwt_payload(session.user_token).get("appKey") or "")
        app_key = str(data.get("app_key") or session.app_key or token_app_key)
        uuid = str(data.get("uuid") or session.uuid)
        secret = str(data.get("secret") or session.secret)
        move_card_raw = data.get("move_card")
        move_card = int(move_card_raw if move_card_raw not in (None, "") else session.move_card or 0)
        dev_muserid = str(data.get("dev_muserid") or session.dev_muserid)
        missing = [name for name, value in (("app_key", app_key), ("uuid", uuid), ("move_card", move_card), ("secret", secret)) if not value]
        if missing:
            return None, missing
        return (
            OpenApiCreds(
                uuid=uuid,
                app_key=app_key,
                move_card=int(move_card),
                secret=secret,
                bases=list(self.openapi_bases),
                dev_muserid=dev_muserid,
            ),
            [],
        )

    def _collect_live_descriptors(self, probe_result: dict[str, Any]) -> list[LiveDescriptor]:
        descriptors: list[LiveDescriptor] = []
        for group, rows in probe_result.items():
            if not str(group).endswith("_results"):
                continue
            if not isinstance(rows, list):
                continue
            for idx, row in enumerate(rows):
                if not isinstance(row, dict):
                    continue
                result = HttpResult(
                    ok=bool(row.get("ok")),
                    url=str(row.get("url") or ""),
                    status=row.get("status"),
                    json_data=row.get("json_data"),
                    text=str(row.get("text") or ""),
                    error=row.get("error"),
                    request_payload=row.get("request_payload"),
                )
                source = f"{group}[{idx}]"
                urls = _dedupe(
                    extract_possible_stream_urls(result.json_data if result.json_data is not None else result.text)
                )
                descriptors.append(
                    LiveDescriptor(
                        endpoint=source,
                        payload=row.get("request_payload") if isinstance(row.get("request_payload"), dict) else {},
                        result=result,
                        urls=urls,
                    )
                )
        return descriptors

    def select_playable_url(self, descriptors: list[LiveDescriptor]) -> PlayableUrlResult:
        candidates: list[tuple[int, str, str]] = []
        for item in descriptors:
            for url in item.urls:
                score, scheme = _score_url(url, item.endpoint)
                if score <= 0:
                    continue
                candidates.append((score, scheme, f"{item.endpoint}|{url}"))
        if not candidates:
            return PlayableUrlResult(
                url="",
                scheme="",
                headers={},
                source_endpoint="",
                confidence=0.0,
                status="no_stream_url",
                note="No URL candidates in live probe response",
            )
        candidates.sort(key=lambda item: item[0], reverse=True)
        score, scheme, packed = candidates[0]
        source, url = packed.split("|", 1)
        status = "ok" if scheme in {"rtsp", "rtsps", "http", "https"} else "unsupported_for_vlc"
        return PlayableUrlResult(
            url=url,
            scheme=scheme,
            headers={},
            source_endpoint=source,
            confidence=round(min(0.99, max(0.05, score / 120)), 3),
            status=status,
            note="" if status == "ok" else f"Best candidate uses {scheme}, which may require WebRTC/session handling",
        )

    def run_cloud_url(
        self,
        account: str,
        password: str,
        device_id: str = "",
        channel: int = 0,
        timeout: int = 20,
        app_key: str = "",
        access_token: str = "",
        iso_code: str = "",
        openapi_overrides: dict[str, Any] | None = None,
        debug: bool = False,
    ) -> dict[str, Any]:
        if access_token:
            session, login_attempts = self.login_with_authorization(
                access_token=access_token,
                app_key=app_key,
                timeout=timeout,
            )
        else:
            session, login_attempts = self.login(
                account=account,
                password=password,
                app_key=app_key,
                iso_code=iso_code,
                timeout=timeout,
            )
        if not any(_is_success(item) for item in login_attempts):
            return {
                "status": "cloud_login_failed",
                "device_id": device_id,
                "session": {
                    "user_token_masked": _mask_secret(session.user_token, 10, 8),
                    "app_key": session.app_key,
                    "vendor": session.vendor,
                    "uuid": session.uuid,
                },
                "diagnostics": {
                    "login_attempts": _summarize_http_results(login_attempts, limit=12),
                },
            }
        session, app_detail_attempts = self.fetch_app_detail(session=session, timeout=timeout)
        discovered_set: set[str] = set(_extract_auth_hints(session.raw_login).device_ids)
        for attempt in login_attempts + app_detail_attempts:
            hints = _extract_auth_hints(attempt.json_data if attempt.json_data is not None else attempt.text)
            discovered_set.update(hints.device_ids)
        discovered = sorted(discovered_set)
        if not device_id:
            return {
                "status": "device_id_required",
                "discovered_devices": discovered,
                "session": {
                    "user_token_masked": _mask_secret(session.user_token, 10, 8),
                    "token_expires_utc": session.token_expires_utc,
                    "app_key": session.app_key,
                    "vendor": session.vendor,
                    "uuid": session.uuid,
                },
                "diagnostics": (
                    {
                        "login_attempts": _summarize_http_results(login_attempts, limit=12),
                        "app_detail_attempts": _summarize_http_results(app_detail_attempts, limit=8),
                    }
                    if debug
                    else {}
                ),
            }

        session, device_token_attempts = self.exchange_device_token(
            session=session,
            device_id=device_id,
            channel=channel,
            timeout=timeout,
        )
        combined_overrides = dict(openapi_overrides or {})
        if app_key and not combined_overrides.get("app_key"):
            combined_overrides["app_key"] = app_key
        creds, missing = self._build_openapi_creds(session, combined_overrides)
        refresh_creds_errors: list[str] = []
        if not creds and self._last_login_kwargs:
            for _ in range(2):
                try:
                    refreshed_session, refresh_attempts = self.refresh_session(timeout=timeout)
                    login_attempts.extend(refresh_attempts)
                    refreshed_session, refresh_app_detail_attempts = self.fetch_app_detail(
                        session=refreshed_session,
                        timeout=timeout,
                    )
                    app_detail_attempts.extend(refresh_app_detail_attempts)
                    refreshed_session, refresh_device_attempts = self.exchange_device_token(
                        session=refreshed_session,
                        device_id=device_id,
                        channel=channel,
                        timeout=timeout,
                    )
                    device_token_attempts.extend(refresh_device_attempts)
                    refreshed_creds, refreshed_missing = self._build_openapi_creds(
                        refreshed_session,
                        combined_overrides,
                    )
                    session = refreshed_session
                    creds, missing = refreshed_creds, refreshed_missing
                    if creds:
                        break
                except Exception as exc:  # noqa: BLE001
                    refresh_creds_errors.append(str(exc))
        if not creds:
            return {
                "status": "openapi_credentials_missing",
                "missing_fields": missing,
                "device_id": device_id,
                "discovered_devices": discovered,
                "session": {
                    "user_token_masked": _mask_secret(session.user_token, 10, 8),
                    "device_token_masked": _mask_secret(session.device_token, 8, 4),
                    "app_key": session.app_key,
                    "vendor": session.vendor,
                    "uuid": session.uuid,
                    "move_card": session.move_card,
                    "secret_masked": _mask_secret(session.secret, 4, 4),
                },
                "diagnostics": {
                    "login_attempts": _summarize_http_results(login_attempts, limit=10),
                    "app_detail_attempts": _summarize_http_results(app_detail_attempts, limit=8),
                    "device_token_attempts": _summarize_http_results(device_token_attempts, limit=10),
                    "refresh_errors": refresh_creds_errors,
                }
                if debug
                else {},
            }

        probe = OpenApiProbe(creds=creds)
        probe_result = probe.run_live_probe(
            device_id=device_id,
            device_user="",
            device_pass="",
            channel=channel,
            timeout=timeout,
        )
        descriptors = self._collect_live_descriptors(probe_result)
        playable = self.select_playable_url(descriptors)

        if (playable.status != "ok" or any(_is_token_error(d.result) for d in descriptors)) and self._last_login_kwargs:
            try:
                refreshed_session, refresh_attempts = self.refresh_session(timeout=timeout)
                refreshed_session, refresh_device_token_attempts = self.exchange_device_token(
                    session=refreshed_session,
                    device_id=device_id,
                    channel=channel,
                    timeout=timeout,
                )
                refreshed_creds, refreshed_missing = self._build_openapi_creds(refreshed_session, combined_overrides)
                if not refreshed_missing and refreshed_creds:
                    refreshed_probe = OpenApiProbe(creds=refreshed_creds)
                    refreshed_probe_result = refreshed_probe.run_live_probe(
                        device_id=device_id,
                        device_user="",
                        device_pass="",
                        channel=channel,
                        timeout=timeout,
                    )
                    refreshed_descriptors = self._collect_live_descriptors(refreshed_probe_result)
                    refreshed_playable = self.select_playable_url(refreshed_descriptors)
                    if refreshed_playable.status == "ok" or playable.status != "ok":
                        session = refreshed_session
                        probe_result = refreshed_probe_result
                        descriptors = refreshed_descriptors
                        playable = refreshed_playable
                    if debug:
                        probe_result["refresh_login_attempts"] = _summarize_http_results(refresh_attempts, limit=6)
                        probe_result["refresh_device_token_attempts"] = _summarize_http_results(
                            refresh_device_token_attempts, limit=6
                        )
            except Exception as exc:  # noqa: BLE001
                if debug:
                    probe_result["refresh_error"] = str(exc)

        possible_urls = sorted({url for item in descriptors for url in item.urls})
        config_summary = probe_result.get("config_summary") if isinstance(probe_result.get("config_summary"), dict) else {}
        rtsp_hint: dict[str, Any] = {}
        if config_summary:
            rtsp_cfg = config_summary.get("rtsp") if isinstance(config_summary.get("rtsp"), dict) else {}
            if rtsp_cfg.get("is_server"):
                rtsp_hint = {
                    "server_enabled": True,
                    "host_hint": str(rtsp_cfg.get("server_address_hint") or ""),
                    "port": rtsp_cfg.get("port"),
                    "auth_type": str(rtsp_cfg.get("auth_type") or ""),
                    "requires_direct_network": True,
                }
                if playable.status != "ok":
                    playable.note = (
                        "OpenAPI exposed RTSP/network config, but the cloud probe did not return a direct playable "
                        "media URL. RTSP likely requires direct access to the device network."
                    )
        output: dict[str, Any] = {
            "status": playable.status,
            "device_id": device_id,
            "discovered_devices": discovered,
            "playable": playable.__dict__,
            "possible_stream_urls": possible_urls,
            "config_summary": config_summary,
            "session": {
                "user_token_masked": _mask_secret(session.user_token, 10, 8),
                "device_token_masked": _mask_secret(session.device_token, 8, 4),
                "token_expires_utc": session.token_expires_utc,
                "app_key": session.app_key,
                "vendor": session.vendor,
                "uuid": session.uuid,
                "move_card": session.move_card,
                "secret_masked": _mask_secret(session.secret, 4, 4),
                "dev_muserid": session.dev_muserid,
            },
        }
        if rtsp_hint:
            output["rtsp_hint"] = rtsp_hint
        if debug:
            output["diagnostics"] = {
                "login_attempts": _summarize_http_results(login_attempts, limit=12),
                "app_detail_attempts": _summarize_http_results(app_detail_attempts, limit=10),
                "device_token_attempts": _summarize_http_results(device_token_attempts, limit=12),
                "live_probe": _sanitize_live_probe(probe_result),
            }
        return output
