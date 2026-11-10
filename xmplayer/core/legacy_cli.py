from __future__ import annotations

import argparse
import base64
import getpass
import html
import json
import os
import re
import socket
import shutil
import subprocess
from pathlib import Path
from typing import Any
from .ams_regions import AmsCache, credential_identity, normalize_ams_base

from .legacy_api import (
    AgentTcpEncryptedClaimProbe,
    AgentTcpLiveProbe,
    AccessServerProbe,
    analyze_live_controller_flow,
    agent_protocol_query,
    BossApi,
    CloudAuthSession,
    CloudLiveExtractor,
    RpsLiveChain,
    OpenApiCreds,
    OpenApiProbe,
    DEFAULT_STATUS_BASE,
    DEFAULT_STATUS_UA,
    _mask_secrets_in_obj,
    _sanitize_live_probe,
    build_6611_login_candidate,
    build_agent_payload_variants,
    build_session_id,
    build_h5_cloud_url,
    derive_futurehome_token_username,
    get_agent_client_uuid,
    _decode_base64_with_suffix,
    _recv_base64_message,
    _summarize_handshake_reply,
    _is_token_error,
    parse_agent_protocol_response,
    parse_status_protocol_response,
    status_protocol_query,
)
from .legacy_parsers import (
    decode_jwt_no_verify,
    extract_default_region_config,
    extract_default_jvss_url,
    extract_access_token,
    jwt_expiry_utc,
    mask_secret,
    parse_devices_from_text,
    parse_login_params,
)


DEFAULT_6611_LOGIN_TYPE = "DVRIP-FutureHome"
DEFAULT_6611_LOGIN_USER_AGENT = "Funv1.6.4f-And32-wR5qH796Ky8D03r"
RPS_CHAIN_RUNTIME_BASELINE = "baseline_20260323"
RPS_CHAIN_RUNTIME_EXPERIMENTAL = "experimental_current"
DEFAULT_CLOUD_LOGIN_FILE = "login.txt"
DEFAULT_ICSEE_APP_KEY = "6475da8c43534b8a8c2813e362dda1cb"
DEFAULT_ICSEE_UUID = "xmeye"
DEFAULT_ICSEE_VENDOR = "General"
DEFAULT_ICSEE_MOVE_CARD = 2
# Verified against current iCSee AMS loginExist traffic in local captures.
DEFAULT_ICSEE_SECRET = "067f8673c2e94d38905dd426ca3a3bfc"
DEFAULT_BASELINE_CONTROLLER_PROFILE = "historical_order_built_queries_dynamic_second582"
DEFAULT_EXPERIMENTAL_CONTROLLER_PROFILE = "first_582_start_random32"
DEFAULT_PHONE_SELECTOR_REFERENCE = "logs/pcap_19_01_43_6510_http_decoded.json"
DEFAULT_PHONE_HANDSHAKE_REFERENCE = "logs/pcap_19_01_43_stream119_decoded.json"


def _read_text(raw: str | None, file_path: str | None) -> str:
    if raw:
        return raw
    if file_path:
        return Path(file_path).read_text(encoding="utf-8", errors="ignore")
    return ""


def _print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def _extract_xworld_string(text: str, key: str) -> str:
    if not text or not key:
        return ""
    pattern = rf'<string name="{re.escape(key)}">(.*?)</string>'
    match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return html.unescape(match.group(1)).strip()


def _parse_int_auto(value: str) -> int:
    return int(str(value).strip(), 0)


def _load_followup_frames(path: str | None, cmd_filter: str | None, max_items: int) -> list[dict[str, Any]]:
    if not path:
        return []
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = (((raw.get("c2s") or {}).get("frames")) or []) if isinstance(raw, dict) else []
    if not isinstance(rows, list):
        return []
    cmd_value = _parse_int_auto(cmd_filter) if cmd_filter else None
    followups: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cmd = int(row.get("cmd") or 0)
        if cmd_value is not None and cmd != cmd_value:
            continue
        payload_text = row.get("payload_text")
        if not isinstance(payload_text, str):
            continue
        followups.append(
            {
                "msg_type": int(row.get("msg_type") or 0),
                "session_id": int(row.get("session_id") or 0),
                "msg_id": int(row.get("msg_id") or 0),
                "unk": int(row.get("unk") or 0),
                "cmd": cmd,
                "code": int(row.get("code_be") or 0),
                "code_endian": "be",
                "payload_bytes": payload_text.encode("utf-8") + b"\x00",
            }
        )
        if len(followups) >= max(1, max_items):
            break
    return followups


def _load_claim_json(raw: str | None, file_path: str | None) -> dict[str, Any]:
    text = _read_text(raw, file_path).strip()
    if not text:
        return {}
    parsed = json.loads(text)
    return parsed if isinstance(parsed, dict) else {}


def _summarize_http_attempts(rows: list[Any], limit: int = 8) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in rows[:limit]:
        out.append(
            {
                "ok": bool(getattr(item, "ok", False)),
                "status": getattr(item, "status", None),
                "url": str(getattr(item, "url", "") or ""),
                "error": getattr(item, "error", None),
                "response_head": str(getattr(item, "text", "") or "")[:160],
            }
        )
    return out


def _resolve_cloud_login_password(
    *,
    explicit_login: str = "",
    explicit_password: str = "",
    login_file: str = DEFAULT_CLOUD_LOGIN_FILE,
) -> tuple[str, str, dict[str, Any]]:
    login = str(explicit_login or "").strip()
    password = str(explicit_password or "")
    if login and password:
        return login, password, {
            "source": "explicit",
            "login_masked": mask_secret(login, 3, 3),
        }
    path = Path(login_file)
    if not path.exists():
        return "", "", {
            "source": "missing",
            "path": str(path),
            "reason": "login_file_missing",
        }
    raw = path.read_text(encoding="utf-8", errors="ignore")
    params = parse_login_params(raw)
    login = str(
        params.get("login")
        or params.get("account")
        or params.get("userName")
        or params.get("username")
        or params.get("email")
        or ""
    ).strip()
    password = str(
        params.get("password")
        or params.get("passwd")
        or params.get("pwd")
        or ""
    )
    if not login or not password:
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        if len(lines) >= 2:
            login = login or lines[0]
            password = password or lines[1]
    if login and password:
        return login, password, {
            "source": "login_file",
            "path": str(path),
            "login_masked": mask_secret(login, 3, 3),
        }
    return "", "", {
        "source": "invalid",
        "path": str(path),
        "reason": "login_file_missing_credentials",
    }


def _default_ams_preauth_context(app_key: str) -> dict[str, Any]:
    return {
        "uuid": DEFAULT_ICSEE_UUID,
        "vendor": DEFAULT_ICSEE_VENDOR,
        "secret": DEFAULT_ICSEE_SECRET,
        "move_card": DEFAULT_ICSEE_MOVE_CARD,
        "app_key": str(app_key or DEFAULT_ICSEE_APP_KEY).strip() or DEFAULT_ICSEE_APP_KEY,
        "source": "icsee_app_defaults",
    }


def _split_handshake_text(raw_text: str) -> dict[str, Any]:
    text = str(raw_text or "")
    terminator = ''
    if text.endswith('XXEE'):
        try:
            text = base64.b64decode(text[:-4], validate=True).decode('utf-8')
            terminator = 'XXEE'
        except (ValueError, UnicodeDecodeError):
            pass
    suffix_text = ""
    if text.endswith("]q\x04"):
        suffix_text = "]q\x04"
        text = text[:-3]
    parts = text.split(":") if text else []
    return {
        "raw_text": str(raw_text or ""),
        "text": text,
        "parts_count": len(parts),
        "authcode": parts[0] if len(parts) >= 1 else "",
        "client_token": parts[1] if len(parts) >= 2 else "",
        "serial": parts[2] if len(parts) >= 3 else "",
        "session": parts[3] if len(parts) >= 4 else "",
        "suffix_text": suffix_text,
        "wire_terminator": terminator,
        "suffix_hex": suffix_text.encode("utf-8", errors="ignore").hex() if suffix_text else "",
        "wire_len": len(str(raw_text or "").encode("utf-8", errors="ignore")),
        "text_len": len(text.encode("utf-8", errors="ignore")),
    }


def _load_phone_selector_reference(path: str) -> dict[str, Any]:
    source = Path(path)
    if not source.exists():
        return {"path": str(source), "exists": False, "streams": [], "rpscmd_attempts": []}
    rows = json.loads(source.read_text(encoding="utf-8"))
    streams: dict[str, dict[str, Any]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        stream_id = str(row.get("stream") or "").strip()
        if not stream_id:
            continue
        entry = streams.setdefault(stream_id, {"stream": stream_id})
        text = str(row.get("text") or "").strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except Exception:
            continue
        proto = parsed.get("AgentProtocol") if isinstance(parsed.get("AgentProtocol"), dict) else {}
        body = proto.get("Body") if isinstance(proto.get("Body"), dict) else {}
        header = proto.get("Header") if isinstance(proto.get("Header"), dict) else {}
        if str(row.get("method") or "").strip():
            entry["request"] = {
                "frame": row.get("frame"),
                "time": row.get("time"),
                "service_type": str(body.get("ServiceType") or ""),
                "authcode": str(body.get("Authcode") or ""),
                "client_token": str(body.get("ClientToken") or ""),
                "session_id": str(body.get("SessionId") or ""),
                "dest_port": str(body.get("DestPort") or ""),
                "step": str(body.get("Step") or ""),
                "encrypt": str(body.get("Encrypt") or ""),
                "protocol_mode": str(body.get("ProtocolMode") or ""),
                "serial_number": str(body.get("SerialNumber") or ""),
            }
        else:
            entry["response"] = {
                "frame": row.get("frame"),
                "time": row.get("time"),
                "error_num": str(header.get("ErrorNum") or ""),
                "agent_server_ip": str(body.get("AgentServerIp") or ""),
                "agent_server_port": str(body.get("AgentServerPort") or ""),
                "random_str": str(body.get("RandomStr") or ""),
                "protocol_mode": str(body.get("ProtocolMode") or ""),
            }
    ordered_streams = sorted(
        [item for item in streams.values() if item.get("request")],
        key=lambda item: str(((item.get("request") or {}).get("time") or "")),
    )
    rpscmd_attempts = [
        item
        for item in ordered_streams
        if str(((item.get("request") or {}).get("service_type") or "")).strip() == "RpsCmd"
    ]
    rpsav_attempts = [
        item
        for item in ordered_streams
        if str(((item.get("request") or {}).get("service_type") or "")).strip() == "RpsAV"
    ]
    sessions = [str(((item.get("request") or {}).get("session_id") or "")) for item in rpscmd_attempts if (item.get("request") or {}).get("session_id")]
    client_tokens = [str(((item.get("request") or {}).get("client_token") or "")) for item in rpscmd_attempts if (item.get("request") or {}).get("client_token")]
    authcodes = [str(((item.get("request") or {}).get("authcode") or "")) for item in rpscmd_attempts if (item.get("request") or {}).get("authcode")]
    return {
        "path": str(source),
        "exists": True,
        "streams": ordered_streams,
        "rpscmd_attempts": rpscmd_attempts,
        "rpsav_attempts": rpsav_attempts,
        "summary": {
            "rpscmd_count": len(rpscmd_attempts),
            "rpsav_count": len(rpsav_attempts),
            "same_client_token_across_rpscmd": len(set(client_tokens)) <= 1 if client_tokens else False,
            "same_authcode_across_rpscmd": len(set(authcodes)) <= 1 if authcodes else False,
            "unique_sessions_across_rpscmd": len(set(sessions)) == len([s for s in sessions if s]) if sessions else False,
            "first_success_attempt_index": next(
                (
                    idx + 1
                    for idx, item in enumerate(rpscmd_attempts)
                    if str((((item.get("response") or {}).get("error_num")) or "")) == "200"
                    and str((((item.get("response") or {}).get("agent_server_ip")) or ""))
                ),
                None,
            ),
        },
    }


def _load_phone_handshake_reference(path: str) -> dict[str, Any]:
    source = Path(path)
    if not source.exists():
        return {"path": str(source), "exists": False}
    rows = json.loads(source.read_text(encoding="utf-8"))
    handshake_tx = next((row for row in rows if isinstance(row, dict) and str(row.get("kind") or "") == "handshake_tx"), {})
    handshake_rx = next((row for row in rows if isinstance(row, dict) and str(row.get("kind") or "") == "handshake_rx"), {})
    parsed_tx = _split_handshake_text(str(handshake_tx.get("raw_text") or ""))
    return {
        "path": str(source),
        "exists": True,
        "handshake_tx": {
            "frame": handshake_tx.get("frame"),
            "time": handshake_tx.get("time"),
            "raw_hex": handshake_tx.get("raw_hex"),
            **parsed_tx,
        },
        "handshake_rx": {
            "frame": handshake_rx.get("frame"),
            "time": handshake_rx.get("time"),
            "raw_text": str(handshake_rx.get("raw_text") or ""),
        },
    }


def _probe_first_6611_handshake(
    *,
    host: str,
    port: int,
    authcode: str,
    client_token: str,
    serial: str,
    session: str,
    timeout: float,
) -> dict[str, Any]:
    probe = AgentTcpLiveProbe()
    handshake_b64 = probe.build_handshake(authcode, client_token, serial, session)
    handshake_text = f"{authcode}:{client_token}:{serial}:{session}"
    sent_info = {
        "sent_b64": handshake_b64.decode("ascii", errors="ignore"),
        "sent_text": handshake_text,
        "sent_wire_text": handshake_b64.decode('ascii'),
        "sent_suffix_hex": probe.suffix.hex(),
    }
    result: dict[str, Any] = {
        "agent_host": host,
        "agent_port": int(port),
        "handshake": dict(sent_info),
    }
    sock = socket.create_connection((host, int(port)), timeout=float(timeout))
    sock.settimeout(float(timeout))
    try:
        sock.sendall(handshake_b64)
        b64_resp, leftover, err = _recv_base64_message(sock, timeout=float(timeout), suffix=probe.suffix)
        if not b64_resp:
            result["handshake"] = {**sent_info, "ok": False, "error": err or "no_response"}
            result["leftover_len"] = len(leftover or b"")
            return result
        decoded, dec_err = _decode_base64_with_suffix(b64_resp, probe.suffix)
        if decoded is None:
            result["handshake"] = {**sent_info, "ok": False, "error": dec_err or "decode_failed"}
            result["leftover_len"] = len(leftover or b"")
            return result
        parsed = probe.parse_handshake_response(decoded)
        result["handshake"] = {
            **sent_info,
            "ok": True,
            "b64_len": len(b64_resp),
            "decoded_len": len(decoded),
            "parsed": parsed,
            **_summarize_handshake_reply(b64_resp, parsed),
        }
        result["leftover_len"] = len(leftover or b"")
        return result
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _run_first_6611_harness(
    *,
    serial_number: str,
    authcode: str,
    server_ip: str,
    server_port: str,
    client_token: str,
    dest_port: str,
    timeout: int,
    attempts: int,
    runtime_mode: str,
    status_user_agent: str,
    content_type: str,
    ssl_verify: bool,
    explicit_session_id: str = "",
    protocol_mode: str = "tcp",
    encrypt: str = "1",
    step: str = "0",
    vendor: str = "",
) -> dict[str, Any]:
    urls = [
        f"https://{server_ip}:{server_port}/",
    ]
    urls = list(dict.fromkeys(urls))
    content_types = list(dict.fromkeys([content_type, "text/html", "application/json"]))
    out: dict[str, Any] = {
        "status": "error",
        "runtime_mode": runtime_mode,
        "server_ip": server_ip,
        "server_port": server_port,
        "client_token_masked": mask_secret(client_token, 8, 4),
        "attempts": [],
    }
    for idx in range(max(1, int(attempts))):
        current_session = explicit_session_id or build_session_id()
        payloads = build_agent_payload_variants(
            authcode=authcode,
            serial_number=serial_number,
            client_token=client_token,
            dest_port=dest_port,
            service_type="RpsCmd",
            session_id=current_session,
            encrypt=encrypt,
            step=step,
            protocol_mode=protocol_mode,
            vendor=vendor,
        )
        selector_runs: list[dict[str, Any]] = []
        selected: dict[str, Any] = {}
        for payload in payloads:
            payload_body = ((payload.get("AgentProtocol") or {}).get("Body") or {}) if isinstance(payload, dict) else {}
            for agent_url in urls:
                for ctype in content_types:
                    res = agent_protocol_query(
                        url=agent_url,
                        payload=payload,
                        timeout=int(timeout),
                        ssl_verify=ssl_verify if agent_url.startswith("https://") else False,
                        user_agent=status_user_agent,
                        content_type=ctype,
                        runtime_mode=runtime_mode,
                    )
                    parsed = parse_agent_protocol_response(res.json_data)
                    item = {
                        "ok": res.ok,
                        "status": res.status,
                        "url": res.url,
                        "content_type": ctype,
                        "service_type": payload_body.get("ServiceType"),
                        "session_id_masked": mask_secret(current_session, 6, 4),
                        "parsed": parsed,
                        "response_head": (res.text or "")[:400],
                        "error": res.error,
                    }
                    selector_runs.append(item)
                    if parsed.get("agent_server_ip") and parsed.get("agent_server_port"):
                        selected = item
                        break
                if selected:
                    break
            if selected:
                break
        attempt_result: dict[str, Any] = {
            "attempt_index": idx + 1,
            "service_type": "RpsCmd",
            "session_id_masked": mask_secret(current_session, 6, 4),
            "selector_attempts": selector_runs,
            "selector_selected": selected,
        }
        parsed = selected.get("parsed") if isinstance(selected.get("parsed"), dict) else {}
        if parsed.get("agent_server_ip") and parsed.get("agent_server_port"):
            handshake_result = _probe_first_6611_handshake(
                host=str(parsed.get("agent_server_ip") or ""),
                port=int(parsed.get("agent_server_port") or 0),
                authcode=authcode,
                client_token=client_token,
                serial=serial_number,
                session=current_session,
                timeout=float(timeout),
            )
            attempt_result["agent_server"] = {
                "ip": parsed.get("agent_server_ip"),
                "port": int(parsed.get("agent_server_port") or 0),
                "random_str": parsed.get("random_str"),
                "protocol_mode": parsed.get("protocol_mode"),
            }
            attempt_result["handshake"] = handshake_result.get("handshake") or {}
            attempt_result["status"] = "handshake_ok" if bool((attempt_result.get("handshake") or {}).get("ok")) else "handshake_timeout"
        else:
            attempt_result["status"] = "selector_failed"
            attempt_result["handshake"] = {}
        out["attempts"].append(attempt_result)
        if bool((attempt_result.get("handshake") or {}).get("ok")):
            out["status"] = "ok"
            out["selected_attempt_index"] = idx + 1
            break
    if out.get("status") != "ok":
        out["status"] = "error"
    return out


def _compare_first_6611_reference(phone_selector: dict[str, Any], phone_handshake: dict[str, Any], desktop: dict[str, Any]) -> dict[str, Any]:
    app_rpscmd = list(phone_selector.get("rpscmd_attempts") or [])
    desktop_attempts = list(desktop.get("attempts") or [])
    app_sessions = [str((((item.get("request") or {}).get("session_id")) or "")) for item in app_rpscmd if ((item.get("request") or {}).get("session_id"))]
    app_client_tokens = [str((((item.get("request") or {}).get("client_token")) or "")) for item in app_rpscmd if ((item.get("request") or {}).get("client_token"))]
    app_authcodes = [str((((item.get("request") or {}).get("authcode")) or "")) for item in app_rpscmd if ((item.get("request") or {}).get("authcode"))]
    desktop_sessions = [str((((item.get("handshake") or {}).get("sent_text") or "")).split(":")[3]) for item in desktop_attempts if ":" in str((item.get("handshake") or {}).get("sent_text") or "")]
    desktop_client_tokens = [str((((item.get("handshake") or {}).get("sent_text") or "")).split(":")[1]) for item in desktop_attempts if ":" in str((item.get("handshake") or {}).get("sent_text") or "")]
    desktop_authcodes = [str((((item.get("handshake") or {}).get("sent_text") or "")).split(":")[0]) for item in desktop_attempts if ":" in str((item.get("handshake") or {}).get("sent_text") or "")]

    desktop_reference_attempt = next(
        (item for item in desktop_attempts if (item.get("handshake") or {}).get("sent_text")),
        desktop_attempts[0] if desktop_attempts else {},
    )
    desktop_handshake = _split_handshake_text(str(((desktop_reference_attempt.get("handshake") or {}).get("sent_wire_text") or "")))
    app_handshake = (phone_handshake.get("handshake_tx") or {}) if isinstance(phone_handshake, dict) else {}

    selector_mismatches: list[str] = []
    if len(app_rpscmd) != len(desktop_attempts):
        selector_mismatches.append(f"rpscmd_attempt_count app={len(app_rpscmd)} desktop={len(desktop_attempts)}")
    if (len(set(app_client_tokens)) <= 1) != (len(set(desktop_client_tokens)) <= 1 if desktop_client_tokens else False):
        selector_mismatches.append("client_token_stability differs")
    if (len(set(app_sessions)) == len(app_sessions) if app_sessions else False) != (
        len(set(desktop_sessions)) == len(desktop_sessions) if desktop_sessions else False
    ):
        selector_mismatches.append("session_rotation differs")

    handshake_mismatches: list[str] = []
    for key in ("parts_count", "serial", "suffix_text", "wire_len"):
        if str(app_handshake.get(key) or "") != str(desktop_handshake.get(key) or ""):
            handshake_mismatches.append(f"{key} app={app_handshake.get(key)!r} desktop={desktop_handshake.get(key)!r}")
    for key in ("authcode", "client_token", "session"):
        if str(app_handshake.get(key) or "") != str(desktop_handshake.get(key) or ""):
            handshake_mismatches.append(f"{key} differs")

    retry_mismatches: list[str] = []
    app_success_idx = phone_selector.get("summary", {}).get("first_success_attempt_index")
    desktop_success_idx = desktop.get("selected_attempt_index")
    if app_success_idx != desktop_success_idx:
        retry_mismatches.append(f"first_success_attempt_index app={app_success_idx} desktop={desktop_success_idx}")

    return {
        "selector_sequence": {
            "app": phone_selector.get("summary") or {},
            "desktop": {
                "rpscmd_count": len(desktop_attempts),
                "same_client_token_across_rpscmd": len(set(desktop_client_tokens)) <= 1 if desktop_client_tokens else False,
                "same_authcode_across_rpscmd": len(set(desktop_authcodes)) <= 1 if desktop_authcodes else False,
                "unique_sessions_across_rpscmd": len(set(desktop_sessions)) == len(desktop_sessions) if desktop_sessions else False,
                "first_success_attempt_index": desktop_success_idx,
            },
            "mismatches": selector_mismatches,
        },
        "handshake_payload": {
            "app": app_handshake,
            "desktop": desktop_handshake,
            "mismatches": handshake_mismatches,
        },
        "retry_semantics": {
            "app": {
                "same_client_token": len(set(app_client_tokens)) <= 1 if app_client_tokens else False,
                "same_authcode": len(set(app_authcodes)) <= 1 if app_authcodes else False,
                "unique_sessions": len(set(app_sessions)) == len(app_sessions) if app_sessions else False,
                "first_success_attempt_index": app_success_idx,
            },
            "desktop": {
                "same_client_token": len(set(desktop_client_tokens)) <= 1 if desktop_client_tokens else False,
                "same_authcode": len(set(desktop_authcodes)) <= 1 if desktop_authcodes else False,
                "unique_sessions": len(set(desktop_sessions)) == len(desktop_sessions) if desktop_sessions else False,
                "first_success_attempt_index": desktop_success_idx,
            },
            "mismatches": retry_mismatches,
        },
    }


def _bootstrap_ams_preauth_context(
    *,
    text: str,
    timeout: int,
    explicit_access_token: str = "",
    explicit_app_key: str = "",
    ssl_verify: bool = True,
) -> tuple[CloudLiveExtractor, CloudAuthSession, list[Any], list[Any], dict[str, Any]]:
    extractor = CloudLiveExtractor()
    resolved_app_key = str(explicit_app_key or "").strip()
    if not resolved_app_key:
        resolved_app_key = DEFAULT_ICSEE_APP_KEY

    login_attempts: list[Any] = []
    app_attempts: list[Any] = []
    defaults = _default_ams_preauth_context(resolved_app_key)
    session = CloudAuthSession(
        account="preauth",
        user_token="",
        app_key=str(defaults.get("app_key") or resolved_app_key),
        vendor=str(defaults.get("vendor") or ""),
        uuid=str(defaults.get("uuid") or DEFAULT_ICSEE_UUID),
        move_card=int(defaults.get("move_card") or DEFAULT_ICSEE_MOVE_CARD),
        secret=str(defaults.get("secret") or ""),
    )
    info: dict[str, Any] = {
        "source": str(defaults.get("source") or "icsee_app_defaults"),
        "app_key": str(session.app_key or resolved_app_key),
        "access_token_present": False,
        "uuid": session.uuid,
        "vendor": session.vendor,
        "move_card": session.move_card,
        "secret_masked": mask_secret(session.secret, 6, 4),
    }
    return extractor, session, login_attempts, app_attempts, info


def _login_cloud_session_for_rps(
    *,
    text: str,
    timeout: int,
    explicit_access_token: str = "",
    explicit_app_key: str = "",
    explicit_login: str = "",
    explicit_password: str = "",
    login_file: str = DEFAULT_CLOUD_LOGIN_FILE,
    ssl_verify: bool = True,
    explicit_ams_base: str = "",
    target_serial: str = "",
) -> tuple[CloudLiveExtractor, Any, list[Any], list[Any], dict[str, Any]]:
    extractor = CloudLiveExtractor()
    resolved_app_key = str(explicit_app_key or "").strip()
    if not resolved_app_key:
        resolved_app_key = DEFAULT_ICSEE_APP_KEY
    login, password, login_info = _resolve_cloud_login_password(
        explicit_login=explicit_login,
        explicit_password=explicit_password,
        login_file=login_file,
    )
    bootstrap_login_attempts: list[Any] = []
    bootstrap_app_attempts: list[Any] = []
    bootstrap_context: dict[str, Any] = {}
    if not (login and password):
        raise RuntimeError("login.txt credentials are required for the self-contained RPS cloud login path")
    extractor, preauth_session, bootstrap_login_attempts, bootstrap_app_attempts, bootstrap_context = _bootstrap_ams_preauth_context(
        text=text,
        timeout=timeout,
        explicit_access_token=explicit_access_token,
        explicit_app_key=resolved_app_key,
        ssl_verify=ssl_verify,
    )
    override = normalize_ams_base(explicit_ams_base or os.environ.get('XMPLAYER_AMS_BASE', ''))
    cache = AmsCache(credential_identity(login, password, resolved_app_key, override))
    extractor.ams_cache = cache
    extractor.ams_base_override = override
    extractor.ams_preferred_base = cache.preferred_region(target_serial)
    login_kwargs = dict(account=login, password=password, app_key=str(preauth_session.app_key or resolved_app_key),
                        uuid=str(preauth_session.uuid or DEFAULT_ICSEE_UUID), secret=str(preauth_session.secret or ''),
                        move_card=int(preauth_session.move_card or 0), vendor=str(preauth_session.vendor or ''),
                        timeout=timeout, ssl_verify=ssl_verify)
    extractor._last_login_kwargs = dict(mode='ams_password', **login_kwargs)
    cached = cache.load_session()
    if cached:
        session = CloudAuthSession(account=login, **cached)
        login_attempts = []
    else:
        session, login_attempts = extractor.login_with_ams_credentials(**login_kwargs)
    mode = "ams_password"
    app_attempts: list[Any] = []
    info = {
        "login_mode": mode,
        "login_source": login_info,
        "app_key": str(session.app_key or resolved_app_key or "").strip(),
        "session_cached": bool(cached),
        "ams_base": session.ams_base or session.ams_login_base,
        "bootstrap_context": bootstrap_context,
        "bootstrap_login_attempts": _summarize_http_attempts(bootstrap_login_attempts),
        "bootstrap_app_attempts": _summarize_http_attempts(bootstrap_app_attempts),
    }
    return extractor, session, login_attempts, app_attempts, info


def _refresh_admin_token_for_rps(
    *,
    text: str,
    serial_number: str,
    timeout: int,
    explicit_access_token: str = "",
    explicit_jvss_base: str = "",
    explicit_login: str = "",
    explicit_password: str = "",
    login_file: str = DEFAULT_CLOUD_LOGIN_FILE,
    explicit_app_key: str = "",
    ssl_verify: bool = True,
    explicit_ams_base: str = "",
) -> tuple[str, dict[str, Any]]:
    jvss_base = (explicit_jvss_base or extract_default_jvss_url(text) or "").strip()
    refresh_info: dict[str, Any] = {
        "attempted": True,
        "mode": "jvss",
        "jvss_base": jvss_base or "default",
    }
    extractor, session, login_attempts, app_attempts, login_context = _login_cloud_session_for_rps(
        text=text,
        timeout=timeout,
        explicit_access_token=explicit_access_token,
        explicit_app_key=explicit_app_key,
        explicit_login=explicit_login,
        explicit_password=explicit_password,
        login_file=login_file,
        ssl_verify=ssl_verify,
        explicit_ams_base=explicit_ams_base,
        target_serial=serial_number,
    )
    uuid_source = "login_session"
    if not session.uuid:
        session.uuid = "xmeye"
        uuid_source = "fallback_default"
    session, jvss_attempts = extractor.fetch_jvss_device_login_token(
        session=session,
        device_id=serial_number,
        timeout=timeout,
        is_latest=True,
        jvss_bases=[jvss_base] if jvss_base else None,
        ssl_verify=ssl_verify,
    )
    if not session.device_token and any(row.status == 401 or _is_token_error(row) for row in jvss_attempts):
        session, refresh_attempts = extractor.refresh_session(timeout=timeout)
        login_attempts.extend(refresh_attempts)
        session, retried = extractor.fetch_jvss_device_login_token(
            session=session, device_id=serial_number, timeout=timeout, is_latest=True,
            jvss_bases=[jvss_base] if jvss_base else None, ssl_verify=ssl_verify,
        )
        jvss_attempts.extend(retried)
    refresh_info.update(
        {
            "auth_chain_mode": str(login_context.get("login_mode") or ""),
            "auth_chain_source": login_context.get("login_source") or {},
            "ams_base": session.ams_base or session.ams_login_base,
            "session_cached": login_context.get('session_cached', False),
            "app_key": str(login_context.get("app_key") or ""),
            "uuid": session.uuid,
            "vendor": session.vendor,
            "uuid_source": uuid_source,
            "move_card": session.move_card,
            "secret_masked": mask_secret(session.secret, 6, 4),
            "login_attempts": _summarize_http_attempts(login_attempts),
            "app_attempts": _summarize_http_attempts(app_attempts),
            "jvss_attempts": _summarize_http_attempts(jvss_attempts),
            "fresh_admin_token_masked": mask_secret(session.device_token, 8, 4) if session.device_token else "",
        }
    )
    return session.device_token, refresh_info


def _refresh_authcode_for_rps(
    *,
    text: str,
    serial_number: str,
    timeout: int,
    explicit_access_token: str = "",
    explicit_ams_base: str = "",
    refresh_mode: str = RPS_CHAIN_RUNTIME_EXPERIMENTAL,
    explicit_login: str = "",
    explicit_password: str = "",
    login_file: str = DEFAULT_CLOUD_LOGIN_FILE,
    explicit_app_key: str = "",
    ssl_verify: bool = True,
) -> tuple[str, dict[str, Any]]:
    normalized_refresh_mode = str(refresh_mode or RPS_CHAIN_RUNTIME_EXPERIMENTAL).strip() or RPS_CHAIN_RUNTIME_EXPERIMENTAL
    refresh_info: dict[str, Any] = {
        "attempted": True,
        "mode": (
            "ams_region_then_msdlist"
            if normalized_refresh_mode == RPS_CHAIN_RUNTIME_BASELINE
            else "ams_region_then_acapp"
        ),
        "ams_base": explicit_ams_base or "default",
    }
    extractor, session, login_attempts, app_attempts, login_context = _login_cloud_session_for_rps(
        text=text,
        timeout=timeout,
        explicit_access_token=explicit_access_token,
        explicit_app_key=explicit_app_key,
        explicit_login=explicit_login,
        explicit_password=explicit_password,
        login_file=login_file,
        ssl_verify=ssl_verify,
        explicit_ams_base=explicit_ams_base,
        target_serial=serial_number,
    )
    session, devices, ams_attempts = extractor.fetch_ams_device_list(
        session=session, timeout=timeout, serial_number=serial_number, ssl_verify=ssl_verify,
    )
    session, acapp_rows, acapp_attempts = extractor.fetch_acapp_auth_list(
        session=session,
        serial_number=serial_number,
        auth_type="rps",
        timeout=timeout,
        ams_bases=[session.ams_base] if devices else None,
        ssl_verify=ssl_verify,
    )
    acapp_match = next(
        (
            row
            for row in acapp_rows
            if str(row.get("_device_id") or row.get("uuid") or row.get("sn") or "").strip() == serial_number
            and (
                str(row.get("_auth_name") or row.get("type") or row.get("authname") or "").strip().lower() in {"", "rps"}
                or str(row.get("rps") or "").strip()
            )
        ),
        {},
    )
    acapp_authcode = str(
        acapp_match.get("_auth_code")
        or acapp_match.get("auth")
        or acapp_match.get("authcode")
        or acapp_match.get("authCode")
        or acapp_match.get("rps")
        or ""
    ).strip()
    matched = next((row for row in devices if str(row.get("_device_id") or "") == serial_number), {})
    ams_authcode = str(matched.get("rps") or "").strip()
    if normalized_refresh_mode == RPS_CHAIN_RUNTIME_BASELINE:
        fresh_authcode = ams_authcode or acapp_authcode
        refresh_source = (
            "ams_refresh"
            if ams_authcode
            else ("acapp_refresh_fallback" if acapp_authcode else "missing")
        )
    else:
        fresh_authcode = acapp_authcode or ams_authcode
        refresh_source = "acapp_refresh" if acapp_authcode else ("ams_refresh" if ams_authcode else "missing")
    refresh_info.update(
        {
            "auth_chain_mode": str(login_context.get("login_mode") or ""),
            "auth_chain_source": login_context.get("login_source") or {},
            "ams_base": session.ams_base or session.ams_login_base,
            "session_cached": login_context.get('session_cached', False),
            "app_key": str(login_context.get("app_key") or ""),
            "source": refresh_source,
            "uuid": session.uuid,
            "vendor": session.vendor,
            "move_card": session.move_card,
            "secret_masked": mask_secret(session.secret, 6, 4),
            "login_attempts": _summarize_http_attempts(login_attempts),
            "app_attempts": _summarize_http_attempts(app_attempts),
            "acapp_attempts": _summarize_http_attempts(acapp_attempts),
            "acapp_rows_seen": len(acapp_rows),
            "acapp_matched_device_id": str(acapp_match.get("_device_id") or ""),
            "acapp_auth_name": str(acapp_match.get("_auth_name") or ("rps" if acapp_authcode else "")),
            "fresh_acapp_authcode_masked": mask_secret(acapp_authcode, 8, 4) if acapp_authcode else "",
            "ams_attempts": _summarize_http_attempts(ams_attempts),
            "devices_seen": len(devices),
            "matched_device_id": str(matched.get("_device_id") or ""),
            "fresh_ams_authcode_masked": mask_secret(ams_authcode, 8, 4) if ams_authcode else "",
            "fresh_authcode_masked": mask_secret(fresh_authcode, 8, 4) if fresh_authcode else "",
            "fresh_share_auth_token_masked": mask_secret(str(matched.get("shareAuthToken") or ""), 8, 4)
            if matched
            else "",
        }
    )
    if acapp_match:
        refresh_info["acapp_selected_auths"] = {
            "uuid": str(acapp_match.get("uuid") or acapp_match.get("sn") or acapp_match.get("_device_id") or ""),
            "rps": str(acapp_match.get("rps") or ""),
            "p2p": str(acapp_match.get("p2p") or acapp_match.get("p2P") or ""),
            "dss": str(acapp_match.get("dss") or ""),
            "css": str(acapp_match.get("css") or ""),
            "tps": str(acapp_match.get("tps") or ""),
            "pms": str(acapp_match.get("pms") or ""),
            "_auth_name": str(acapp_match.get("_auth_name") or ""),
            "_auth_code": str(acapp_match.get("_auth_code") or ""),
        }
    if matched:
        refresh_info["matched_device"] = {
            "group": str(matched.get("_group") or ""),
            "uuid": str(matched.get("uuid") or matched.get("sn") or matched.get("devSn") or ""),
            "rps_masked": mask_secret(str(matched.get("rps") or ""), 8, 4) if matched.get("rps") else "",
            "p2p_masked": mask_secret(str(matched.get("p2P") or matched.get("p2p") or ""), 8, 4)
            if (matched.get("p2P") or matched.get("p2p"))
            else "",
        }
        refresh_info["matched_device_auths"] = {
            "uuid": str(matched.get("uuid") or matched.get("sn") or matched.get("devSn") or ""),
            "rps": str(matched.get("rps") or ""),
            "p2p": str(matched.get("p2P") or matched.get("p2p") or ""),
            "dss": str(matched.get("dss") or ""),
            "css": str(matched.get("css") or ""),
            "tps": str(matched.get("tps") or ""),
            "pms": str(matched.get("pms") or ""),
        }
    return fresh_authcode, refresh_info


def _find_first_frame(path: str | None, cmd_filter: int) -> dict[str, Any]:
    if not path:
        return {}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = (((raw.get("c2s") or {}).get("frames")) or []) if isinstance(raw, dict) else []
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if int(row.get("cmd") or 0) != cmd_filter:
            continue
        return row
    return {}


def _sanitize_login_candidate_result(result: dict[str, Any], secrets: list[str]) -> dict[str, Any]:
    sanitized = json.loads(json.dumps(result, ensure_ascii=False))
    for key in ("communicate_key_raw", "transport_key_raw"):
        if sanitized.get(key):
            sanitized[key] = mask_secret(str(sanitized[key]), 2, 2)
    for key in ("candidate_json_text",):
        if sanitized.get(key):
            sanitized[key] = _mask_secrets_in_obj(sanitized[key], secrets)
    if isinstance(sanitized.get("candidate_json"), dict):
        sanitized["candidate_json"] = _mask_secrets_in_obj(sanitized["candidate_json"], secrets)
    if isinstance(sanitized.get("claim_summary"), dict):
        sanitized["claim_summary"] = _mask_secrets_in_obj(sanitized["claim_summary"], secrets)
    return _mask_secrets_in_obj(sanitized, secrets)


def cmd_token_info(args: argparse.Namespace) -> int:
    payload = decode_jwt_no_verify(args.token)
    out = {
        "token_masked": mask_secret(args.token, 10, 8),
        "payload": payload,
        "expiry_utc": jwt_expiry_utc(args.token),
    }
    _print_json(out)
    return 0


def cmd_parse_login_params(args: argparse.Namespace) -> int:
    text = _read_text(args.raw, args.file)
    params = parse_login_params(text)
    access_token = params.get("accessToken") or extract_access_token(text)
    out = {
        "params": params,
        "access_token": access_token,
        "access_token_masked": mask_secret(access_token, 10, 8),
        "jwt_payload": decode_jwt_no_verify(access_token) if access_token else {},
        "jwt_expiry_utc": jwt_expiry_utc(access_token) if access_token else "",
    }
    _print_json(out)
    return 0


def cmd_parse_device_list(args: argparse.Namespace) -> int:
    text = _read_text(args.raw, args.file)
    devices = [d.as_dict() for d in parse_devices_from_text(text)]
    for item in devices:
        for key in ("share_auth_token", "admin_token", "password", "pms", "rps", "dss", "tps", "css", "p2p"):
            item[key] = mask_secret(item.get(key, ""), 8, 4) if item.get(key) else ""
    _print_json({"count": len(devices), "devices": devices})
    return 0


def cmd_boss_login(args: argparse.Namespace) -> int:
    if args.payload_json:
        payloads = [json.loads(args.payload_json)]
    else:
        payloads = BossApi.guess_login_payloads(
            account=args.account,
            password=args.password,
            app_key=args.app_key or "",
            iso_code=args.iso_code or "",
        )
    api = BossApi(base_urls=args.boss_base or None)
    results = api.experimental_login(payloads=payloads, timeout=args.timeout)
    summary = []
    for item in results:
        code = None
        if isinstance(item.json_data, dict):
            code = item.json_data.get("code")
        summary.append(
            {
                "ok": item.ok,
                "status": item.status,
                "code": code,
                "url": item.url,
                "request_payload": item.request_payload,
                "response_head": (item.text or "")[:500],
                "error": item.error,
            }
        )
    _print_json({"attempts": len(summary), "results": summary})
    return 0


def cmd_live_probe(args: argparse.Namespace) -> int:
    creds = OpenApiCreds(
        uuid=args.uuid,
        app_key=args.app_key,
        move_card=int(args.move_card),
        secret=args.secret,
        bases=args.openapi_base or None,
    )
    probe = OpenApiProbe(creds=creds)
    raw_result = probe.run_live_probe(
        device_id=args.device_id,
        device_user=args.device_user or "",
        device_pass=args.device_pass or "",
        channel=args.channel,
        timeout=args.timeout,
    )
    result = _sanitize_live_probe(raw_result)
    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_json(result)
    return 0


def cmd_h5_url(args: argparse.Namespace) -> int:
    url = build_h5_cloud_url(
        access_token=args.token,
        app_key=args.app_key,
        lang=args.lang,
        app_scheme=args.app_scheme,
        app_ver=args.app_ver,
        base=args.base,
    )
    print(url)
    return 0


def _resolve_vlc_path(custom_path: str | None) -> str:
    if custom_path:
        p = Path(custom_path).expanduser()
        return str(p)
    from_path = shutil.which("vlc")
    if from_path:
        return from_path
    candidates = [
        Path("C:/Program Files/VideoLAN/VLC/vlc.exe"),
        Path("C:/Program Files (x86)/VideoLAN/VLC/vlc.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return ""


def _launch_vlc(url: str, vlc_path: str) -> dict[str, Any]:
    cmd = [vlc_path, "--network-caching=300", url]
    try:
        subprocess.Popen(cmd)  # noqa: S603
        return {"launched": True, "command": cmd, "error": ""}
    except Exception as exc:  # noqa: BLE001
        return {"launched": False, "command": cmd, "error": str(exc)}


def cmd_cloud_url(args: argparse.Namespace) -> int:
    access_token = (args.access_token or "").strip()
    login = (args.login or "").strip()
    password = args.password or ""
    if not access_token:
        if not login:
            login = input("iCSee login: ").strip()
        if not password:
            password = getpass.getpass("iCSee password: ")
        if not login or not password:
            print("login/password are required (or use --access-token)")
            return 2

    extractor = CloudLiveExtractor(
        boss_bases=args.boss_base or None,
        openapi_bases=args.openapi_base or None,
    )
    overrides = {
        "app_key": args.app_key or "",
        "uuid": args.uuid or "",
        "move_card": args.move_card,
        "secret": args.secret or "",
        "dev_muserid": args.dev_muserid or "",
    }
    # Drop empty override fields to keep diagnostics clear.
    overrides = {k: v for k, v in overrides.items() if v not in ("", None)}

    try:
        result = extractor.run_cloud_url(
            account=login,
            password=password,
            device_id=args.device_id or "",
            channel=int(args.channel),
            timeout=args.timeout,
            app_key=args.app_key or "",
            access_token=access_token,
            iso_code=args.iso_code or "",
            openapi_overrides=overrides,
            debug=bool(args.debug),
        )
    except Exception as exc:  # noqa: BLE001
        out = {
            "status": "cloud_login_failed",
            "error": str(exc),
        }
        _print_json(out)
        return 1

    status = str(result.get("status") or "")
    vlc_result: dict[str, Any] = {}
    playable = result.get("playable") if isinstance(result.get("playable"), dict) else {}
    url = str(playable.get("url") or "")
    if args.launch_vlc and url and status == "ok":
        vlc_path = _resolve_vlc_path(args.vlc_path)
        if vlc_path:
            vlc_result = _launch_vlc(url=url, vlc_path=vlc_path)
        else:
            vlc_result = {
                "launched": False,
                "error": "VLC not found; use --vlc-path",
                "command": ["vlc", "--network-caching=300", url],
            }
    elif args.launch_vlc:
        vlc_result = {
            "launched": False,
            "error": "No VLC-compatible URL to launch",
            "command": [],
        }

    if vlc_result:
        result["vlc"] = vlc_result
    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_json(result)

    if status == "ok":
        return 0
    if status in {"device_id_required", "unsupported_for_vlc", "openapi_credentials_missing"}:
        return 2
    return 1


def _pick_device_from_text(text: str, device_id: str | None) -> Any | None:
    devices = parse_devices_from_text(text)
    if not devices:
        return None
    if device_id:
        for item in devices:
            if item.dev_id == device_id:
                return item
        return None
    return devices[0]


def cmd_access_pms_probe(args: argparse.Namespace) -> int:
    text = _read_text(args.raw, args.file)
    device = _pick_device_from_text(text, args.device_id)

    device_id = (args.device_id or (device.dev_id if device else "")).strip()
    if not device_id:
        print("device-id is required (or provide --file/--raw with device list)")
        return 2

    token_from = (args.token_from or "rps").strip()
    authcode = (args.authcode or (getattr(device, token_from, "") if device else "")).strip()
    if not authcode:
        print("authcode is required (--authcode or device list containing token field)")
        return 2

    dest_port = str(args.dest_port or (device.port if device and device.port else "34567")).strip()
    service_type = (args.service_type or "RpsCmd").strip()
    client_token = (args.client_token or get_agent_client_uuid()).strip()
    session_id = (args.session_id or build_session_id()).strip()

    payloads = build_agent_payload_variants(
        authcode=authcode,
        serial_number=device_id,
        client_token=client_token,
        dest_port=dest_port,
        service_type=service_type,
        session_id=session_id,
        encrypt=str(args.encrypt or "1"),
        step=str(args.step or "0"),
        protocol_mode=str(args.protocol_mode or "tcp"),
        vendor=str(args.vendor or ""),
    )

    probe = AccessServerProbe(bases=args.access_base or None)
    results = probe.probe_agent_protocol(payloads=payloads, timeout=args.timeout, ssl_verify=not args.insecure)

    secrets = [authcode, client_token]
    summarized = []
    parsed = []
    for res in results:
        parsed_item = parse_agent_protocol_response(res.json_data)
        parsed.append(parsed_item)
        summarized.append(
            {
                "ok": res.ok,
                "status": res.status,
                "url": res.url,
                "request_payload": _mask_secrets_in_obj(res.request_payload, secrets),
                "agent_protocol": _mask_secrets_in_obj(parsed_item, secrets),
                "response_head": (res.text or "")[:400],
                "error": res.error,
            }
        )

    agent_pick = None
    for item in parsed:
        if item.get("agent_server_ip") and item.get("agent_server_port"):
            agent_pick = item
            break
    success = False
    if agent_pick:
        err = str(agent_pick.get("error_num"))
        success = err in {"200", "0", "OK", "ok"}
    out = {
        "status": "ok" if success else "no_agent_server",
        "device_id": device_id,
        "service_type": service_type,
        "dest_port": dest_port,
        "client_token_masked": mask_secret(client_token, 8, 4),
        "authcode_masked": mask_secret(authcode, 8, 4),
        "session_id_masked": mask_secret(session_id, 6, 4),
        "agent_server": agent_pick or {},
        "attempts": summarized,
    }
    if args.out:
        Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_json(out)
    return 0 if success else 1


def cmd_status_probe(args: argparse.Namespace) -> int:
    text = _read_text(args.raw, args.file)
    device = _pick_device_from_text(text, args.device_id)

    serial_number = (args.device_id or (device.dev_id if device else "")).strip()
    if not serial_number:
        print("device-id is required (or provide --file/--raw with device list)")
        return 2

    authcode = (args.authcode or (getattr(device, args.token_from, "") if device else "")).strip()
    if not authcode:
        print("authcode is required (--authcode or device list containing token field)")
        return 2

    res = status_protocol_query(
        serial_number=serial_number,
        authcode=authcode,
        base=args.status_base,
        timeout=int(args.timeout),
        ssl_verify=not args.insecure,
        user_agent=args.user_agent,
        content_type=args.content_type,
        manufacturer=str(getattr(args, "manufacturer", "") or "").strip(),
    )
    parsed = parse_status_protocol_response(res.json_data)
    out = {
        "ok": res.ok,
        "status": res.status,
        "url": res.url,
        "authcode_masked": mask_secret(authcode, 8, 4),
        "manufacturer": str(getattr(args, "manufacturer", "") or "").strip(),
        "parsed": parsed,
        "response_head": (res.text or "")[:400],
        "error": res.error,
    }
    if args.out:
        Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_json(out)
    return 0 if res.ok else 1


def cmd_first_6611_harness(args: argparse.Namespace) -> int:
    text = _read_text(args.raw, args.file)
    device = _pick_device_from_text(text, args.device_id)

    serial_number = (args.device_id or (device.dev_id if device else "")).strip()
    if not serial_number:
        print("device-id is required (or provide --file/--raw with device list)")
        return 2

    runtime_mode = str(getattr(args, "runtime_mode", RPS_CHAIN_RUNTIME_BASELINE) or RPS_CHAIN_RUNTIME_BASELINE).strip()
    authcode = (args.authcode or (getattr(device, args.token_from, "") if device else "")).strip()
    authcode_source = "explicit" if args.authcode else ("device_list" if authcode else "missing")
    authcode_refresh: dict[str, Any] = {"attempted": False, "reason": "skipped"}
    if not args.authcode:
        try:
            fresh_authcode, refresh_info = _refresh_authcode_for_rps(
                    text=text,
                    serial_number=serial_number,
                    timeout=max(int(args.timeout), 12),
                    explicit_access_token=(getattr(args, "access_token", None) or "").strip(),
                    explicit_login=str(getattr(args, "cloud_login", "") or "").strip(),
                    explicit_password=str(getattr(args, "cloud_password", "") or ""),
                    login_file=str(getattr(args, "cloud_login_file", DEFAULT_CLOUD_LOGIN_FILE) or DEFAULT_CLOUD_LOGIN_FILE),
                    explicit_app_key=(getattr(args, "app_key", None) or "").strip(),
                    refresh_mode=runtime_mode,
                    ssl_verify=not args.insecure,
            )
            authcode_refresh = refresh_info
            if fresh_authcode:
                authcode = fresh_authcode
                authcode_source = str(refresh_info.get("source") or "ams_refresh")
        except Exception as exc:  # noqa: BLE001
            authcode_refresh = {"attempted": True, "error": str(exc)}
    if not authcode:
        print("authcode is required (--authcode or current AMS refresh path must succeed)")
        return 2

    server_ip = str(getattr(args, "server_ip", None) or "").strip()
    server_port = str(getattr(args, "server_port", None) or "").strip()
    status_result: dict[str, Any] = {}
    if not (server_ip and server_port):
        status_res = status_protocol_query(
            serial_number=serial_number,
            authcode=authcode,
            base=args.status_base,
            timeout=int(args.timeout),
            ssl_verify=not args.insecure,
            user_agent=args.user_agent,
            content_type=args.content_type,
        )
        status_parsed = parse_status_protocol_response(status_res.json_data)
        status_result = {
            "ok": status_res.ok,
            "status": status_res.status,
            "url": status_res.url,
            "parsed": status_parsed,
            "error": status_res.error,
        }
        body = (status_parsed.get("body") or []) if isinstance(status_parsed, dict) else []
        for item in body:
            if not isinstance(item, dict):
                continue
            if str(item.get("SerialNumber") or "").strip() == serial_number:
                server_ip = str(item.get("ServerIP") or "").strip()
                server_port = str(item.get("ServerPort") or "").strip()
                break
        if not (server_ip and server_port):
            out = {
                "status": "error",
                "reason": "server_missing",
                "status_query": status_result,
                "authcode_source": authcode_source,
                "authcode_refresh": authcode_refresh,
            }
            if args.out:
                Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
            _print_json(out)
            return 1

    client_token = (args.client_token or get_agent_client_uuid()).strip()
    harness = _run_first_6611_harness(
        serial_number=serial_number,
        authcode=authcode,
        server_ip=server_ip,
        server_port=server_port,
        client_token=client_token,
        dest_port=str(args.dest_port or (device.port if device and device.port else "34567")),
        timeout=int(args.timeout),
        attempts=int(args.attempts),
        runtime_mode=runtime_mode,
        status_user_agent=args.user_agent,
        content_type=args.content_type,
        ssl_verify=not args.insecure,
        explicit_session_id=str(args.session_id or "").strip(),
        protocol_mode=str(args.protocol_mode or "tcp"),
        encrypt=str(args.encrypt or "1"),
        step=str(args.step or "0"),
        vendor=str(args.vendor or ""),
    )
    phone_selector = _load_phone_selector_reference(str(args.phone_selector_file or DEFAULT_PHONE_SELECTOR_REFERENCE))
    phone_handshake = _load_phone_handshake_reference(str(args.phone_handshake_file or DEFAULT_PHONE_HANDSHAKE_REFERENCE))
    comparison = _compare_first_6611_reference(phone_selector, phone_handshake, harness)
    out = {
        "status": harness.get("status"),
        "runtime_mode": runtime_mode,
        "serial_number": serial_number,
        "status_query": status_result,
        "server_ip": server_ip,
        "server_port": server_port,
        "authcode_masked": mask_secret(authcode, 8, 4),
        "authcode_source": authcode_source,
        "authcode_refresh": authcode_refresh,
        "desktop_harness": harness,
        "phone_reference": {
            "selector_sequence": phone_selector,
            "successful_handshake": phone_handshake,
        },
        "comparison": comparison,
    }
    if args.out:
        Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_json(out)
    return 0 if harness.get("status") == "ok" else 1


def cmd_rps_chain_probe(args: argparse.Namespace) -> int:
    text = _read_text(args.raw, args.file)
    device = _pick_device_from_text(text, args.device_id)

    serial_number = (args.device_id or (device.dev_id if device else "")).strip()
    if not serial_number:
        print("device-id is required (or provide --file/--raw with device list)")
        return 2

    runtime_mode = str(
        getattr(args, "runtime_mode", RPS_CHAIN_RUNTIME_BASELINE) or RPS_CHAIN_RUNTIME_BASELINE
    ).strip() or RPS_CHAIN_RUNTIME_BASELINE
    baseline_runtime = runtime_mode == RPS_CHAIN_RUNTIME_BASELINE
    authcode = (args.authcode or (getattr(device, args.token_from, "") if device else "")).strip()

    chain = RpsLiveChain(
        status_base=args.status_base,
        status_user_agent=args.user_agent,
        status_content_type=args.content_type,
        status_ssl_verify=not args.insecure,
        agent_ssl_verify=not args.insecure,
    )

    default_controller_profile = (
        DEFAULT_BASELINE_CONTROLLER_PROFILE if baseline_runtime else DEFAULT_EXPERIMENTAL_CONTROLLER_PROFILE
    )
    selected_controller_profile = str(
        getattr(args, "controller_profile", default_controller_profile) or default_controller_profile
    ).strip() or default_controller_profile

    attempts_arg = getattr(args, "attempts", None)
    default_attempts = 1 if baseline_runtime else 4
    attempts = max(1, int(attempts_arg if attempts_arg is not None else default_attempts))
    results: list[dict[str, Any]] = []
    dest_port = str(args.dest_port or (device.port if device and device.port else "34567"))
    msg_id = _parse_int_auto(args.msg_id) if args.msg_id else 0x18
    code = _parse_int_auto(args.code) if args.code else 0x00008505
    encrypted_session_int = _parse_int_auto(args.encrypted_session_int) if args.encrypted_session_int else 0x1869F
    if args.encrypted_msg_id:
        encrypted_msg_id = _parse_int_auto(args.encrypted_msg_id)
    elif selected_controller_profile == "app_reference_first_6611":
        encrypted_msg_id = 0x30
    else:
        encrypted_msg_id = 0x10
    encrypted_unk = _parse_int_auto(args.encrypted_unk) if args.encrypted_unk else 0x63
    encrypted_cmd = _parse_int_auto(args.encrypted_cmd) if args.encrypted_cmd else 0x0585
    encrypted_stream_type = (args.encrypted_stream_type or "Main").strip() or "Main"
    encrypted_combine_mode = (args.encrypted_combine_mode or "CONNECT_ALL").strip() or "CONNECT_ALL"
    encrypted_trans_mode = (args.encrypted_trans_mode or "TCP").strip() or "TCP"
    login_username = (getattr(args, "login_username", None) or (device.username if device else "") or "").strip()
    login_password = (
        getattr(args, "login_password", None)
        if getattr(args, "login_password", None) is not None
        else (device.password if device else "")
    )
    explicit_admin_token = (getattr(args, "admin_token", None) or "").strip()
    admin_token = explicit_admin_token or (device.admin_token if device else "") or ""
    admin_token = admin_token.strip()
    admin_token_source = "explicit" if explicit_admin_token else ("device_list" if admin_token else "missing")
    admin_token_refresh: dict[str, Any] = {"attempted": False, "reason": "skipped"}
    authcode_source = "explicit" if args.authcode else ("device_list" if authcode else "missing")
    authcode_refresh: dict[str, Any] = {"attempted": False, "reason": "skipped"}
    if not args.authcode:
        try:
            should_refresh_authcode = (not baseline_runtime) or (not authcode)
            explicit_cloud_login = str(getattr(args, "cloud_login", "") or "").strip()
            explicit_cloud_password = str(getattr(args, "cloud_password", "") or "")
            cloud_login_file = str(getattr(args, "cloud_login_file", DEFAULT_CLOUD_LOGIN_FILE) or DEFAULT_CLOUD_LOGIN_FILE)
            if not should_refresh_authcode:
                login_txt_login, login_txt_password, _ = _resolve_cloud_login_password(
                    explicit_login=explicit_cloud_login,
                    explicit_password=explicit_cloud_password,
                    login_file=cloud_login_file,
                )
                should_refresh_authcode = bool(login_txt_login and login_txt_password)
            if should_refresh_authcode:
                refresh_timeout = max(int(args.timeout), 12)
                fresh_authcode, refresh_info = _refresh_authcode_for_rps(
                    text=text,
                    serial_number=serial_number,
                    timeout=refresh_timeout,
                    explicit_access_token=(getattr(args, "access_token", None) or "").strip(),
                    explicit_login=explicit_cloud_login,
                    explicit_password=explicit_cloud_password,
                    login_file=cloud_login_file,
                    explicit_app_key=(getattr(args, "app_key", None) or "").strip(),
                    refresh_mode=runtime_mode,
                    ssl_verify=not args.insecure,
                )
                authcode_refresh = refresh_info
                if fresh_authcode:
                    authcode = fresh_authcode
                    authcode_source = str(refresh_info.get("source") or "ams_refresh")
            else:
                authcode_refresh = {
                    "attempted": False,
                    "mode": "device_list_baseline",
                    "reason": "baseline_preserved_device_list_authcode",
                }
        except Exception as exc:  # noqa: BLE001
            authcode_refresh = {
                "attempted": True,
                "mode": (
                    "ams_msdlist_then_acapp_fallback"
                    if baseline_runtime
                    else "acapp_then_ams_msdlist"
                ),
                "error": str(exc),
            }
    if (
        args.tcp_mode in {"encrypted", "both"}
        and not explicit_admin_token
        and not bool(getattr(args, "no_admin_token_refresh", False))
    ):
        try:
            fresh_admin_token, refresh_info = _refresh_admin_token_for_rps(
                text=text,
                serial_number=serial_number,
                timeout=int(args.timeout),
                explicit_access_token=(getattr(args, "access_token", None) or "").strip(),
                explicit_jvss_base=(getattr(args, "jvss_base", None) or "").strip(),
                explicit_login=str(getattr(args, "cloud_login", "") or "").strip(),
                explicit_password=str(getattr(args, "cloud_password", "") or ""),
                login_file=str(getattr(args, "cloud_login_file", DEFAULT_CLOUD_LOGIN_FILE) or DEFAULT_CLOUD_LOGIN_FILE),
                explicit_app_key=(getattr(args, "app_key", None) or "").strip(),
                ssl_verify=not args.insecure,
            )
            admin_token_refresh = refresh_info
            if fresh_admin_token:
                admin_token = fresh_admin_token
                admin_token_source = "jvss_refresh"
        except Exception as exc:  # noqa: BLE001
            admin_token_refresh = {
                "attempted": True,
                "mode": "jvss",
                "error": str(exc),
            }
    if not authcode:
        print("authcode is required (--authcode or current AMS refresh path must succeed)")
        return 2
    resolved_app_key = str(getattr(args, "app_key", "") or "").strip()
    if not resolved_app_key:
        resolved_app_key = str(admin_token_refresh.get("app_key") or "").strip()
    if not resolved_app_key:
        resolved_app_key = str((decode_jwt_no_verify((getattr(args, "access_token", None) or "").strip()) or {}).get("appKey") or "").strip()
    resolved_developer_id = str(getattr(args, "developer_id", "") or "").strip()
    if not resolved_developer_id:
        resolved_developer_id = str(admin_token_refresh.get("uuid") or "").strip()
    if not resolved_developer_id and resolved_app_key:
        resolved_developer_id = "xmeye"
    resolved_vendor = str(getattr(args, "vendor", "") or "").strip()
    if not resolved_vendor:
        resolved_vendor = str(admin_token_refresh.get("vendor") or "").strip()
    if not resolved_vendor and not baseline_runtime:
        resolved_vendor = "General"
    region_config = extract_default_region_config(text)
    resolved_gwm_ams_url = str(getattr(args, "gwm_ams_url", "") or "").strip()
    if not resolved_gwm_ams_url and isinstance(region_config, dict):
        resolved_gwm_ams_url = str(region_config.get("amsUrl") or "").strip()
    resolved_device_oem_id = str(getattr(args, "oem_id", "") or "").strip()
    if not resolved_device_oem_id:
        resolved_device_oem_id = _extract_xworld_string(text, f"DEV_MFRS_OEM_ID{serial_number}")
    resolved_device_hardware = str(getattr(args, "device_hardware", "") or "").strip()
    if not resolved_device_hardware:
        resolved_device_hardware = _extract_xworld_string(text, f"device_hardware{serial_number}")
    token_username = (getattr(args, "token_username", None) or "").strip()
    if not token_username and admin_token:
        token_username = derive_futurehome_token_username(serial_number, admin_token)
    encrypted_login_followup: dict[str, Any] | None = None
    if args.tcp_mode in {"encrypted", "both"} and (admin_token or login_password or token_username or login_username):
        encrypted_login_followup = {
            "username": login_username,
            "password": login_password or "",
            "admin_token": admin_token,
            "login_type": (getattr(args, "login_type", None) or DEFAULT_6611_LOGIN_TYPE).strip() or DEFAULT_6611_LOGIN_TYPE,
            "token_username": token_username,
            "user_agent": (getattr(args, "login_user_agent", None) or DEFAULT_6611_LOGIN_USER_AGENT).strip()
            or DEFAULT_6611_LOGIN_USER_AGENT,
            "communicate_key": (getattr(args, "communicate_key", None) or "").strip(),
            "transport_key": (getattr(args, "transport_key", None) or "").strip(),
            "mode": (getattr(args, "login_mode", None) or "auto").strip() or "auto",
        }
        if selected_controller_profile == "app_reference_first_6611":
            encrypted_login_followup.setdefault("msg_id", 0x38)
    encrypted_followup_frames = _load_followup_frames(
        args.followup_file,
        args.followup_cmd,
        int(args.followup_max),
    )

    # Keep one logical client identity across retries, but rotate the session id.
    # Phone captures show stable client token across related 6611 flows, while the
    # per-flow session string changes.
    base_client_token = (args.client_token or get_agent_client_uuid()).strip()
    explicit_session_id = (args.session_id or "").strip()

    for idx in range(attempts):
        client_token = base_client_token
        session_id = explicit_session_id or build_session_id()
        result = chain.run(
            serial_number=serial_number,
            authcode=authcode,
            status_server_ip=(getattr(args, "server_ip", None) or "").strip(),
            status_server_port=str(getattr(args, "server_port", None) or "").strip(),
            client_token=client_token,
            session_id=session_id,
            dest_port=dest_port,
            service_type=args.service_type,
            encrypt=str(args.encrypt or "1"),
            step=str(args.step or "0"),
            protocol_mode=str(args.protocol_mode or "tcp"),
            vendor=resolved_vendor,
            developer_id=resolved_developer_id,
            app_key=resolved_app_key,
            timeout=int(args.timeout),
            channel=int(args.channel),
            stream_type=args.stream_type,
            trans_mode=args.trans_mode,
            combine_mode=args.combine_mode,
            msg_id=msg_id,
            code=code,
            code_endian=args.code_endian,
            capture_seconds=float(args.capture_seconds),
            max_frames=int(args.max_frames),
            tcp_mode=args.tcp_mode,
            encrypted_session_int=encrypted_session_int,
            encrypted_msg_id=encrypted_msg_id,
            encrypted_unk=encrypted_unk,
            encrypted_cmd=encrypted_cmd,
            encrypted_claim_random_a=(args.claim_random_a or "").strip(),
            encrypted_session_hex_width=int(args.encrypted_session_hex_width),
            encrypted_stream_type=encrypted_stream_type,
            encrypted_combine_mode=encrypted_combine_mode,
            encrypted_trans_mode=encrypted_trans_mode,
            encrypted_followup_frames=encrypted_followup_frames,
            encrypted_followup_delay=float(args.followup_delay),
            encrypted_login_followup=encrypted_login_followup,
            encrypted_controller_auto=bool(getattr(args, "controller_auto", False)),
            encrypted_controller_profile=selected_controller_profile,
            plain_handoff=bool(getattr(args, "plain_handoff", False)),
            plain_handoff_trigger=str(getattr(args, "plain_handoff_trigger", "after_second_413") or "after_second_413"),
            gwm_ams_url=resolved_gwm_ams_url,
            device_oem_id=resolved_device_oem_id,
            device_hardware=resolved_device_hardware,
            device_idr_auto_wakeup=bool(device.idr_auto_wakeup) if device else False,
            wakeup_probe_enabled=not bool(getattr(args, "no_wakeup_probe", False)),
            wakeup_host=str(getattr(args, "wakeup_host", "") or "").strip(),
            wakeup_port=int(getattr(args, "wakeup_port", 0) or 0),
            runtime_mode=runtime_mode,
        )
        result["attempt_index"] = idx + 1
        result["runtime_mode"] = runtime_mode
        result["authcode_masked"] = mask_secret(authcode, 8, 4)
        result["authcode_source"] = authcode_source
        result["authcode_refresh"] = authcode_refresh
        result["client_token_masked"] = mask_secret(client_token, 8, 4)
        result["session_id_masked"] = mask_secret(session_id, 6, 4)
        result["admin_token_masked"] = mask_secret(admin_token, 8, 4) if admin_token else ""
        result["admin_token_source"] = admin_token_source
        result["admin_token_refresh"] = admin_token_refresh
        result["developer_id"] = resolved_developer_id or ""
        result["vendor"] = resolved_vendor or ""
        result["app_key_masked"] = mask_secret(resolved_app_key, 6, 4) if resolved_app_key else ""
        result["gwm_ams_url"] = resolved_gwm_ams_url or ""
        result["device_oem_id"] = resolved_device_oem_id or ""
        result["device_hardware"] = resolved_device_hardware or ""
        result["device_support_rps_video"] = bool(device.support_rps_video) if device else False
        result["device_idr_auto_wakeup"] = bool(device.idr_auto_wakeup) if device else False
        results.append(result)

        frames = ((result.get("tcp_probe") or {}).get("frames") or {})
        enc_frames = ((result.get("tcp_encrypted_probe") or {}).get("frames") or {})
        handoff_frames = ((result.get("tcp_plain_handoff_probe") or {}).get("frames") or {})
        if bool(getattr(args, "plain_handoff", False)):
            if (
                int(handoff_frames.get("data") or 0) > 0
                or str(((result.get("tcp_plain_handoff_probe") or {}).get("status") or "")) == "ok"
            ):
                break
        else:
            if (
                result.get("status") == "ok"
                or int(frames.get("data") or 0) > 0
                or int(enc_frames.get("control") or 0) > 0
                or int(handoff_frames.get("data") or 0) > 0
            ):
                break

    result = results[-1]
    if attempts > 1:
        result = {
            "status": "ok" if any(item.get("status") == "ok" for item in results) else result.get("status"),
            "attempts": results,
            "authcode_masked": mask_secret(authcode, 8, 4),
            "authcode_source": authcode_source,
            "authcode_refresh": authcode_refresh,
            "admin_token_masked": mask_secret(admin_token, 8, 4) if admin_token else "",
            "admin_token_source": admin_token_source,
            "admin_token_refresh": admin_token_refresh,
            "device_support_rps_video": bool(device.support_rps_video) if device else False,
            "device_idr_auto_wakeup": bool(device.idr_auto_wakeup) if device else False,
            "runtime_mode": runtime_mode,
        }
    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_json(result)
    return 0 if result.get("status") == "ok" else 1


def cmd_agent_live_probe(args: argparse.Namespace) -> int:
    text = _read_text(args.raw, args.file)
    device = _pick_device_from_text(text, args.device_id)

    device_id = (args.device_id or (device.dev_id if device else "")).strip()
    if not device_id:
        print("device-id is required (or provide --file/--raw with device list)")
        return 2

    authcode = (args.authcode or (getattr(device, args.token_from, "") if device else "")).strip()
    if not authcode:
        print("authcode is required (--authcode or device list containing token field)")
        return 2

    agent_host = (args.agent_host or "").strip()
    if not agent_host:
        print("agent-host is required (Agent server IP from access-pms or pcap)")
        return 2

    client_token = (args.client_token or get_agent_client_uuid()).strip()
    session_id = (args.session_id or build_session_id()).strip()
    session_int = _parse_int_auto(args.session_int) if args.session_int else 0x78
    msg_id = _parse_int_auto(args.msg_id) if args.msg_id else 0x18
    code = _parse_int_auto(args.code) if args.code else 0x00008505

    probe = AgentTcpLiveProbe()
    result = probe.run_probe(
        host=agent_host,
        port=int(args.agent_port),
        authcode=authcode,
        client_token=client_token,
        serial=device_id,
        session=session_id,
        session_int=session_int,
        channel=int(args.channel),
        stream_type=args.stream_type,
        trans_mode=args.trans_mode,
        combine_mode=args.combine_mode,
        msg_id=msg_id,
        code=code,
        code_endian=args.code_endian,
        timeout=float(args.timeout),
        capture_seconds=float(args.capture_seconds),
        max_frames=int(args.max_frames),
        session_hex_width=int(args.session_hex_width),
    )
    result["controller_summary"] = analyze_live_controller_flow(result)

    result["authcode_masked"] = mask_secret(authcode, 8, 4)
    result["client_token_masked"] = mask_secret(client_token, 8, 4)
    result["session_id_masked"] = mask_secret(session_id, 6, 4)

    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_json(result)
    return 0 if result.get("status") == "ok" else 1


def cmd_agent_encrypted_probe(args: argparse.Namespace) -> int:
    text = _read_text(args.raw, args.file)
    device = _pick_device_from_text(text, args.device_id)

    device_id = (args.device_id or (device.dev_id if device else "")).strip()
    if not device_id:
        print("device-id is required (or provide --file/--raw with device list)")
        return 2

    authcode = (args.authcode or (getattr(device, args.token_from, "") if device else "")).strip()
    if not authcode:
        print("authcode is required (--authcode or device list containing token field)")
        return 2

    agent_host = (args.agent_host or "").strip()
    if not agent_host:
        print("agent-host is required (Agent server IP from 6510/pub-status chain or pcap)")
        return 2

    xor_key = (args.xor_key or "").strip()
    if not xor_key:
        print("xor-key is required (RandomStr from 6510 AgentProtocol response)")
        return 2

    client_token = (args.client_token or get_agent_client_uuid()).strip()
    session_id = (args.session_id or build_session_id()).strip()
    session_int = _parse_int_auto(args.session_int) if args.session_int else 0x1869F
    msg_id = _parse_int_auto(args.msg_id) if args.msg_id else 0x10
    unk = _parse_int_auto(args.unk) if args.unk else 0x63
    cmd = _parse_int_auto(args.cmd) if args.cmd else 0x0585
    claim_random_a = (args.claim_random_a or build_session_id(4)).strip()
    followup_frames = _load_followup_frames(
        args.followup_file,
        args.followup_cmd,
        int(args.followup_max),
    )

    probe = AgentTcpEncryptedClaimProbe()
    result = probe.run_probe(
        host=agent_host,
        port=int(args.agent_port),
        authcode=authcode,
        client_token=client_token,
        serial=device_id,
        session=session_id,
        xor_key=xor_key,
        claim_random_a=claim_random_a,
        session_int=session_int,
        channel=int(args.channel),
        stream_type=args.stream_type,
        trans_mode=args.trans_mode,
        combine_mode=args.combine_mode,
        msg_id=msg_id,
        unk=unk,
        cmd=cmd,
        timeout=float(args.timeout),
        capture_seconds=float(args.capture_seconds),
        max_frames=int(args.max_frames),
        session_hex_width=int(args.session_hex_width),
        followup_frames=followup_frames,
        followup_delay=float(args.followup_delay),
        controller_auto=bool(getattr(args, "controller_auto", False)),
        controller_profile=str(getattr(args, "controller_profile", "first_582_start_random32") or "first_582_start_random32"),
    )
    result["controller_summary"] = analyze_live_controller_flow(result)

    result["authcode_masked"] = mask_secret(authcode, 8, 4)
    result["client_token_masked"] = mask_secret(client_token, 8, 4)
    result["session_id_masked"] = mask_secret(session_id, 6, 4)
    result["xor_key_masked"] = mask_secret(xor_key, 2, 2)

    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_json(result)
    return 0 if result.get("status") == "ok" else 1


def cmd_build_6611_login(args: argparse.Namespace) -> int:
    text = _read_text(args.raw, args.file)
    device = _pick_device_from_text(text, args.device_id)
    if device is None:
        print("device-id is required (or provide --file/--raw with device list containing the target device)")
        return 2

    claim_source = _load_claim_json(args.claim_raw, args.claim_file)
    if not claim_source:
        print("claim-json is required (--claim-file or --claim-raw)")
        return 2

    username = (args.username or device.username or "").strip()
    password = args.password if args.password is not None else device.password
    admin_token = (args.admin_token or device.admin_token or "").strip()
    random_a = (args.random_a or "").strip()
    random_b = (args.random_b or "").strip()
    user_agent = (args.user_agent or "").strip()
    communicate_key = (args.communicate_key or "").strip()
    transport_key = (args.transport_key or "").strip()
    token_username = (args.token_username or "").strip()
    msg_type = _parse_int_auto(args.msg_type) if args.msg_type else 0
    session_id = _parse_int_auto(args.session_int) if args.session_int else 0
    msg_id = _parse_int_auto(args.msg_id) if args.msg_id else 0x80
    unk = _parse_int_auto(args.unk) if args.unk else 0x63
    cmd = _parse_int_auto(args.cmd) if args.cmd else 0x03E8

    built = build_6611_login_candidate(
        claim_source=claim_source,
        device_id=device.dev_id,
        username=username,
        password=password or "",
        admin_token=admin_token,
        login_type=args.login_type,
        token_username=token_username,
        random_a=random_a,
        random_b=random_b,
        user_agent=user_agent,
        communicate_key=communicate_key,
        transport_key=transport_key,
        mode=args.mode,
        msg_type=msg_type,
        session_id=session_id,
        msg_id=msg_id,
        unk=unk,
        cmd=cmd,
    )

    compare: dict[str, Any] = {}
    compare_frame = _find_first_frame(args.compare_file, cmd)
    if compare_frame:
        candidate_transport = built.get("transport") if isinstance(built.get("transport"), dict) else {}
        candidate_frame = built.get("frame") if isinstance(built.get("frame"), dict) else {}
        compare = {
            "file": args.compare_file,
            "cmd": cmd,
            "actual": {
                "msg_type": compare_frame.get("msg_type"),
                "session_id": compare_frame.get("session_id"),
                "msg_id": compare_frame.get("msg_id"),
                "unk": compare_frame.get("unk"),
                "payload_len": compare_frame.get("payload_len"),
                "payload_base64_len": compare_frame.get("payload_base64_len"),
                "payload_head_hex": compare_frame.get("payload_head_hex"),
                "payload_base64_head_hex": compare_frame.get("payload_base64_head_hex"),
            },
            "candidate": {
                "msg_type": candidate_frame.get("msg_type"),
                "session_id": candidate_frame.get("session_id"),
                "msg_id": candidate_frame.get("msg_id"),
                "unk": candidate_frame.get("unk"),
                "payload_len": candidate_transport.get("payload_len"),
                "payload_base64_len": candidate_transport.get("payload_b64_len"),
                "payload_head_hex": (
                    str(candidate_transport.get("payload_text") or "").encode("utf-8")[:32].hex()
                    if candidate_transport.get("payload_text")
                    else ""
                ),
                "payload_base64_head_hex": (
                    base64.b64decode(str(candidate_transport.get("payload_text") or ""))[:32].hex()
                    if candidate_transport.get("mode") != "plain" and candidate_transport.get("payload_text")
                    else ""
                ),
            },
        }
        compare["delta"] = {
            "payload_len": int(compare["candidate"]["payload_len"] or 0) - int(compare["actual"]["payload_len"] or 0),
            "payload_base64_len": int(compare["candidate"]["payload_base64_len"] or 0)
            - int(compare["actual"]["payload_base64_len"] or 0),
        }

    out = {
        "status": built.get("status"),
        "device_id": device.dev_id,
        "mode_requested": args.mode,
        "inputs": {
            "username": username,
            "password": password or "",
            "admin_token": admin_token,
            "random_a": random_a,
            "random_b": random_b,
            "user_agent": user_agent,
            "token_username": token_username,
            "communicate_key": communicate_key,
            "transport_key": transport_key,
        },
        "result": built,
        "compare": compare,
    }
    secrets = [password or "", admin_token, communicate_key]
    if transport_key:
        secrets.append(transport_key)
    sanitized = _sanitize_login_candidate_result(out, [s for s in secrets if s])
    if args.out:
        Path(args.out).write_text(json.dumps(sanitized, ensure_ascii=False, indent=2), encoding="utf-8")
    _print_json(sanitized)
    return 0 if built.get("status") == "ok" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="iCSee desktop reverse-engineering helper")
    sub = parser.add_subparsers(dest="command", required=True)

    token_info = sub.add_parser("token-info", help="Decode JWT access token payload")
    token_info.add_argument("--token", required=True)
    token_info.set_defaults(func=cmd_token_info)

    parse_login = sub.add_parser("parse-login-params", help="Parse loginType=&&accessToken=... string")
    parse_login.add_argument("--raw")
    parse_login.add_argument("--file")
    parse_login.set_defaults(func=cmd_parse_login_params)

    parse_devices = sub.add_parser("parse-device-list", help="Extract deviceListJson entries from text/logs")
    parse_devices.add_argument("--raw")
    parse_devices.add_argument("--file")
    parse_devices.set_defaults(func=cmd_parse_device_list)

    boss_login = sub.add_parser("boss-login", help="Experimental /account/userToken/login probe")
    boss_login.add_argument("--account")
    boss_login.add_argument("--password")
    boss_login.add_argument("--app-key")
    boss_login.add_argument("--iso-code")
    boss_login.add_argument("--payload-json", help="Use custom payload JSON instead of guessed payloads")
    boss_login.add_argument("--boss-base", action="append", help="Override boss base URL; repeatable")
    boss_login.add_argument("--timeout", type=int, default=20)
    boss_login.set_defaults(func=cmd_boss_login)

    live_probe = sub.add_parser("live-probe", help="Probe openApi /gwp/v3/rtc/device/* endpoints")
    live_probe.add_argument("--device-id", required=True)
    live_probe.add_argument("--uuid", required=True)
    live_probe.add_argument("--app-key", required=True)
    live_probe.add_argument("--move-card", required=True, type=int)
    live_probe.add_argument("--secret", required=True)
    live_probe.add_argument("--device-user")
    live_probe.add_argument("--device-pass")
    live_probe.add_argument("--channel", type=int)
    live_probe.add_argument("--openapi-base", action="append", help="Override openApi base URL; repeatable")
    live_probe.add_argument("--timeout", type=int, default=20)
    live_probe.add_argument("--out", help="Write full JSON result to file")
    live_probe.set_defaults(func=cmd_live_probe)

    h5_url = sub.add_parser("h5-url", help="Build H5 cloud URL from token/appKey")
    h5_url.add_argument("--token", required=True)
    h5_url.add_argument("--app-key", required=True)
    h5_url.add_argument("--lang", default="ru")
    h5_url.add_argument("--app-scheme", default="icsee.boss.jftech.com")
    h5_url.add_argument("--app-ver", default="7.7.7")
    h5_url.add_argument("--base", default="https://boss-api-as.jftechsoft.com/index")
    h5_url.set_defaults(func=cmd_h5_url)

    cloud_url = sub.add_parser("cloud-url", help="Desktop-only cloud login -> live URL extraction (+ optional VLC launch)")
    cloud_url.add_argument("--access-token", help="Use existing iCSee access token instead of login/password")
    cloud_url.add_argument("--login", help="iCSee account/login")
    cloud_url.add_argument("--password", help="iCSee password (if omitted, prompt securely)")
    cloud_url.add_argument("--device-id", help="Target device serial ID; if omitted, print discovered IDs")
    cloud_url.add_argument("--channel", type=int, default=0)
    cloud_url.add_argument("--launch-vlc", action="store_true", help="Launch VLC automatically when URL is extracted")
    cloud_url.add_argument("--vlc-path", help="Custom path to vlc executable")
    cloud_url.add_argument("--boss-base", action="append", help="Override boss base URL; repeatable")
    cloud_url.add_argument("--openapi-base", action="append", help="Override openApi base URL; repeatable")
    cloud_url.add_argument("--timeout", type=int, default=20)
    cloud_url.add_argument("--app-key", help="Optional appKey override")
    cloud_url.add_argument("--uuid", help="Optional uuid override")
    cloud_url.add_argument("--move-card", type=int, help="Optional moveCard override")
    cloud_url.add_argument("--secret", help="Optional secret override")
    cloud_url.add_argument("--dev-muserid", help="Optional devMuserid/muserid override")
    cloud_url.add_argument("--iso-code", help="Optional country/isoCode hint")
    cloud_url.add_argument("--debug", action="store_true")
    cloud_url.add_argument("--out", help="Write full JSON result to file")
    cloud_url.set_defaults(func=cmd_cloud_url)

    access_pms = sub.add_parser("access-pms-probe", help="Probe access-pms AgentProtocol flow (desktop-only)")
    access_pms.add_argument("--device-id", help="Device serial (SN)")
    access_pms.add_argument("--authcode", help="Authcode token (usually rps token for RpsCmd)")
    access_pms.add_argument(
        "--token-from",
        default="rps",
        help="Pick token from device list when --authcode is omitted (rps/pms/dss/tps/css/p2p)",
    )
    access_pms.add_argument("--service-type", default="RpsCmd", help="ServiceType value (default: RpsCmd)")
    access_pms.add_argument("--dest-port", type=int, help="Device TCP port (default: 34567)")
    access_pms.add_argument("--client-token", help="ClientToken/UUID override")
    access_pms.add_argument("--session-id", help="SessionId override (default: random)")
    access_pms.add_argument("--encrypt", help="Encrypt flag (default: 1)")
    access_pms.add_argument("--step", help="Step value (default: 0)")
    access_pms.add_argument("--protocol-mode", help="ProtocolMode optional value (default: tcp)")
    access_pms.add_argument("--vendor", help="Vendor optional value")
    access_pms.add_argument("--access-base", action="append", help="Override access base URL; repeatable")
    access_pms.add_argument("--insecure", action="store_true", help="Disable TLS verification for https access bases")
    access_pms.add_argument("--timeout", type=int, default=20)
    access_pms.add_argument("--raw", help="Raw deviceListJson/logcat text (optional)")
    access_pms.add_argument("--file", help="Path to deviceListJson/logcat file (optional)")
    access_pms.add_argument("--out", help="Write full JSON result to file")
    access_pms.set_defaults(func=cmd_access_pms_probe)

    status_probe = sub.add_parser("status-probe", help="Query pub-status -> ServerIP/ServerPort for device")
    status_probe.add_argument("--device-id", help="Device serial (SN)")
    status_probe.add_argument("--authcode", help="Authcode token (usually rps)")
    status_probe.add_argument(
        "--token-from",
        default="rps",
        help="Pick token from device list when --authcode is omitted (rps/pms/dss/tps/css/p2p)",
    )
    status_probe.add_argument("--status-base", default=DEFAULT_STATUS_BASE)
    status_probe.add_argument("--user-agent", default=DEFAULT_STATUS_UA)
    status_probe.add_argument("--content-type", default="text/html")
    status_probe.add_argument("--manufacturer", help="Optional Manufacturer field for StatusProtocol body")
    status_probe.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    status_probe.add_argument("--timeout", type=int, default=20)
    status_probe.add_argument("--raw", help="Raw deviceListJson/logcat text (optional)")
    status_probe.add_argument("--file", help="Path to deviceListJson/logcat file (optional)")
    status_probe.add_argument("--out", help="Write full JSON result to file")
    status_probe.set_defaults(func=cmd_status_probe)

    first_6611 = sub.add_parser(
        "first-6611-harness",
        help="Narrow harness for pub-status -> 6510 RpsCmd selector -> first 6611 handshake, plus app-vs-desktop comparison",
    )
    first_6611.add_argument("--device-id", help="Device serial (SN)")
    first_6611.add_argument("--authcode", help="Authcode token (usually rps)")
    first_6611.add_argument(
        "--token-from",
        default="rps",
        help="Pick token from device list when --authcode is omitted (rps/pms/dss/tps/css/p2p)",
    )
    first_6611.add_argument("--client-token", help="ClientToken override")
    first_6611.add_argument("--session-id", help="Handshake session override; if omitted, rotates per attempt")
    first_6611.add_argument("--dest-port", type=int, help="Device TCP port (default: 34567)")
    first_6611.add_argument("--encrypt", help="Encrypt flag (default: 1)")
    first_6611.add_argument("--step", help="Step value (default: 0)")
    first_6611.add_argument("--protocol-mode", default="tcp")
    first_6611.add_argument("--vendor", help="Optional Vendor value for selector request")
    first_6611.add_argument("--status-base", default=DEFAULT_STATUS_BASE)
    first_6611.add_argument("--server-ip", help="Bypass pub-status and use this known 6510 server IP directly")
    first_6611.add_argument("--server-port", help="Bypass pub-status and use this known 6510 server port directly")
    first_6611.add_argument("--user-agent", default=DEFAULT_STATUS_UA)
    first_6611.add_argument("--content-type", default="text/html")
    first_6611.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    first_6611.add_argument("--timeout", type=int, default=15)
    first_6611.add_argument("--attempts", type=int, default=3, help="RpsCmd selector+handshake attempts against the same 6510")
    first_6611.add_argument(
        "--runtime-mode",
        default=RPS_CHAIN_RUNTIME_BASELINE,
        choices=[RPS_CHAIN_RUNTIME_BASELINE, RPS_CHAIN_RUNTIME_EXPERIMENTAL],
    )
    first_6611.add_argument("--cloud-login", help="Cloud account login/email; if omitted, login.txt is used")
    first_6611.add_argument("--cloud-password", help="Cloud account password; if omitted, login.txt is used")
    first_6611.add_argument("--cloud-login-file", default=DEFAULT_CLOUD_LOGIN_FILE)
    first_6611.add_argument("--access-token", help="Optional override, mostly for diagnostics")
    first_6611.add_argument("--app-key", help="Optional app_key override")
    first_6611.add_argument("--phone-selector-file", default=DEFAULT_PHONE_SELECTOR_REFERENCE)
    first_6611.add_argument("--phone-handshake-file", default=DEFAULT_PHONE_HANDSHAKE_REFERENCE)
    first_6611.add_argument("--raw", help="Raw deviceListJson/logcat text (optional)")
    first_6611.add_argument("--file", help="Path to deviceListJson/logcat file (optional)")
    first_6611.add_argument("--out", help="Write full JSON result to file")
    first_6611.set_defaults(func=cmd_first_6611_harness)

    rps_chain = sub.add_parser("rps-chain-probe", help="Run pub-status -> 6510 AgentProtocol -> 6611 TCP probe")
    rps_chain.add_argument("--device-id", help="Device serial (SN)")
    rps_chain.add_argument("--authcode", help="Authcode token (usually rps)")
    rps_chain.add_argument(
        "--token-from",
        default="rps",
        help="Pick token from device list when --authcode is omitted (rps/pms/dss/tps/css/p2p)",
    )
    rps_chain.add_argument("--client-token", help="ClientToken override")
    rps_chain.add_argument("--session-id", help="Handshake session string override")
    rps_chain.add_argument("--dest-port", type=int, help="Device TCP port (default: 34567)")
    rps_chain.add_argument("--service-type", default="RpsCmd")
    rps_chain.add_argument("--encrypt", help="Encrypt flag (default: 1)")
    rps_chain.add_argument("--step", help="Step value (default: 0)")
    rps_chain.add_argument("--protocol-mode", default="tcp")
    rps_chain.add_argument("--vendor", help="Optional Vendor value for AgentProtocol selector requests")
    rps_chain.add_argument("--oem-id", help="Optional OEM/manufacturer hint for STATUS_IDR pre-query")
    rps_chain.add_argument("--device-hardware", help="Optional device_hardware hint for STATUS_IDR pre-query")
    rps_chain.add_argument("--developer-id", help="Optional developer_id for SDK-style bind/session handshakes")
    rps_chain.add_argument("--app-key", help="Optional app_key for SDK-style bind/session handshakes")
    rps_chain.add_argument("--gwm-ams-url", help="Override regional GWM/start_video_req AMS base URL")
    rps_chain.add_argument("--wakeup-host", help="Override STATUS_IDR wakeup host (default: access-pms.secu100.net)")
    rps_chain.add_argument("--wakeup-port", type=int, help="Override STATUS_IDR wakeup port (default: 6602)")
    rps_chain.add_argument("--no-wakeup-probe", action="store_true", help="Skip raw STATUS_IDR/access-pms wakeup before retrying GWM")
    rps_chain.add_argument("--status-base", default=DEFAULT_STATUS_BASE)
    rps_chain.add_argument("--server-ip", help="Bypass pub-status and use this known 6510 server IP directly")
    rps_chain.add_argument("--server-port", help="Bypass pub-status and use this known 6510 server port directly")
    rps_chain.add_argument("--user-agent", default=DEFAULT_STATUS_UA)
    rps_chain.add_argument("--content-type", default="text/html")
    rps_chain.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    rps_chain.add_argument("--timeout", type=int, default=20)
    rps_chain.add_argument(
        "--runtime-mode",
        default=RPS_CHAIN_RUNTIME_BASELINE,
        choices=[RPS_CHAIN_RUNTIME_BASELINE, RPS_CHAIN_RUNTIME_EXPERIMENTAL],
        help="Runtime profile: baseline_20260323 restores the March control-path defaults; experimental_current keeps the newer phone-trace experiments",
    )
    rps_chain.add_argument("--channel", type=int, default=0)
    rps_chain.add_argument("--stream-type", default="Extra1")
    rps_chain.add_argument("--trans-mode", default="TCP")
    rps_chain.add_argument("--combine-mode", default="NONE")
    rps_chain.add_argument("--tcp-mode", default="plain", choices=["plain", "encrypted", "both"])
    rps_chain.add_argument("--msg-id", help="OPMonitor msg_id/seq (default: 0x18)")
    rps_chain.add_argument("--code", help="OPMonitor code field (default: 0x00008505)")
    rps_chain.add_argument("--code-endian", default="be", choices=["be", "le"])
    rps_chain.add_argument("--claim-random-a", help="Encrypted Claim DHParameter.RandomStrA override")
    rps_chain.add_argument("--encrypted-session-int", help="Encrypted Claim session int (default: 0x1869f)")
    rps_chain.add_argument("--encrypted-session-hex-width", type=int, default=10)
    rps_chain.add_argument("--encrypted-msg-id", help="Encrypted Claim msg_id/seq (default: 0x10)")
    rps_chain.add_argument("--encrypted-unk", help="Encrypted Claim FF01 unk field (default: 0x63)")
    rps_chain.add_argument("--encrypted-cmd", help="Encrypted Claim FF01 cmd field (default: 0x0585)")
    rps_chain.add_argument("--encrypted-stream-type", help="Encrypted Claim stream type (default: Main)")
    rps_chain.add_argument("--encrypted-combine-mode", help="Encrypted Claim combine mode (default: CONNECT_ALL)")
    rps_chain.add_argument("--encrypted-trans-mode", help="Encrypted Claim transport mode (default: TCP)")
    rps_chain.add_argument("--login-mode", choices=["auto", "token", "password"], default="auto")
    rps_chain.add_argument("--login-type", default=DEFAULT_6611_LOGIN_TYPE)
    rps_chain.add_argument("--login-username", help="Override device username for dynamic cmd=0x03e8 builder")
    rps_chain.add_argument("--login-password", help="Override device password for dynamic cmd=0x03e8 builder")
    rps_chain.add_argument("--admin-token", help="Override AdminToken for dynamic cmd=0x03e8 builder")
    rps_chain.add_argument("--access-token", help="Override account access token for desktop JVSS AdminToken refresh")
    rps_chain.add_argument("--jvss-base", help="Override JVSS base URL for desktop AdminToken refresh")
    rps_chain.add_argument("--no-admin-token-refresh", action="store_true", help="Skip automatic JVSS refresh and use cached AdminToken only")
    rps_chain.add_argument("--token-username", help="Override decoded TOKEN-mode UserName for DVRIP-FutureHome")
    rps_chain.add_argument("--login-user-agent", default=DEFAULT_6611_LOGIN_USER_AGENT)
    rps_chain.add_argument("--cloud-login", help="Cloud account login/email; if omitted, login.txt is used when present")
    rps_chain.add_argument("--cloud-password", help="Cloud account password; if omitted, login.txt is used when present")
    rps_chain.add_argument(
        "--cloud-login-file",
        default=DEFAULT_CLOUD_LOGIN_FILE,
        help="Path to cloud login file (default: login.txt, first two non-empty lines: login/password)",
    )
    rps_chain.add_argument("--communicate-key", help="Override raw 16-byte CommunicateKey seed")
    rps_chain.add_argument("--transport-key", help="Override outer AES key for cmd=0x03e8")
    rps_chain.add_argument("--followup-file", help="Decoded 6611 JSON capture to replay c2s frames from after Claim")
    rps_chain.add_argument("--followup-cmd", help="Only replay frames with this cmd (for example 0x03e8)")
    rps_chain.add_argument("--followup-max", type=int, default=1)
    rps_chain.add_argument("--followup-delay", type=float, default=0.0)
    rps_chain.add_argument("--controller-auto", action="store_true", help="After successful login, auto-send the best known first 0x582 controller candidate")
    rps_chain.add_argument(
        "--plain-handoff",
        action="store_true",
        help="After encrypted controller_readying, run a second 6510->plain 6611 live handoff using the historical Extra1/NONE claim",
    )
    rps_chain.add_argument(
        "--plain-handoff-trigger",
        default="after_second_413",
        choices=[
            "after_login",
            "after_first_followup",
            "after_second_413",
            "after_third_413",
            "after_third_413_gap",
            "after_sixth_413",
            "after_post582_cluster",
            "after_583",
            "after_61b",
            "after_readying_101",
            "after_late_064d",
            "after_second_success_replay",
        ],
        help="When to start the second plain handoff relative to encrypted controller progress",
    )
    rps_chain.add_argument(
        "--controller-profile",
        default="historical_order_built_queries_dynamic_second582",
        help="Auto-controller profile (default: historical_order_built_queries_dynamic_second582)",
    )
    rps_chain.add_argument("--capture-seconds", type=float, default=5.0)
    rps_chain.add_argument("--max-frames", type=int, default=200)
    rps_chain.add_argument(
        "--attempts",
        type=int,
        default=None,
        help="Repeat whole pub-status -> selector flow; default is 1 in baseline_20260323 and 4 in experimental_current",
    )
    rps_chain.add_argument("--raw", help="Raw deviceListJson/logcat text (optional)")
    rps_chain.add_argument("--file", help="Path to deviceListJson/logcat file (optional)")
    rps_chain.add_argument("--out", help="Write full JSON result to file")
    rps_chain.set_defaults(func=cmd_rps_chain_probe)

    agent_live = sub.add_parser("agent-live-probe", help="Probe TCP 6611 live handshake + OPMonitor start")
    agent_live.add_argument("--agent-host", help="Agent server IP (from access-pms or pcap)")
    agent_live.add_argument("--agent-port", type=int, default=6611)
    agent_live.add_argument("--device-id", help="Device serial (SN)")
    agent_live.add_argument("--authcode", help="Authcode token (usually rps)")
    agent_live.add_argument(
        "--token-from",
        default="rps",
        help="Pick token from device list when --authcode is omitted (rps/pms/dss/tps/css/p2p)",
    )
    agent_live.add_argument("--client-token", help="ClientToken override")
    agent_live.add_argument("--session-id", help="Handshake session string override")
    agent_live.add_argument("--session-int", help="OPMonitor session int (default: 0x78)")
    agent_live.add_argument("--session-hex-width", type=int, default=10)
    agent_live.add_argument("--channel", type=int, default=0)
    agent_live.add_argument("--stream-type", default="Extra1")
    agent_live.add_argument("--trans-mode", default="TCP")
    agent_live.add_argument("--combine-mode", default="NONE")
    agent_live.add_argument("--msg-id", help="OPMonitor msg_id/seq (default: 0x18)")
    agent_live.add_argument("--code", help="OPMonitor code field (default: 0x00008505)")
    agent_live.add_argument("--code-endian", default="be", choices=["be", "le"])
    agent_live.add_argument("--timeout", type=float, default=10)
    agent_live.add_argument("--capture-seconds", type=float, default=5.0)
    agent_live.add_argument("--max-frames", type=int, default=200)
    agent_live.add_argument("--raw", help="Raw deviceListJson/logcat text (optional)")
    agent_live.add_argument("--file", help="Path to deviceListJson/logcat file (optional)")
    agent_live.add_argument("--out", help="Write full JSON result to file")
    agent_live.set_defaults(func=cmd_agent_live_probe)

    agent_encrypted = sub.add_parser("agent-encrypted-probe", help="Probe TCP 6611 encrypted OPMonitor Claim preflight")
    agent_encrypted.add_argument("--agent-host", help="Agent server IP (from 6510/pub-status chain or pcap)")
    agent_encrypted.add_argument("--agent-port", type=int, default=6611)
    agent_encrypted.add_argument("--device-id", help="Device serial (SN)")
    agent_encrypted.add_argument("--authcode", help="Authcode token (usually rps)")
    agent_encrypted.add_argument(
        "--token-from",
        default="rps",
        help="Pick token from device list when --authcode is omitted (rps/pms/dss/tps/css/p2p)",
    )
    agent_encrypted.add_argument("--client-token", help="ClientToken override")
    agent_encrypted.add_argument("--session-id", help="Handshake session string override")
    agent_encrypted.add_argument("--xor-key", help="XOR key from 6510 AgentProtocol RandomStr")
    agent_encrypted.add_argument("--claim-random-a", help="DHParameter.RandomStrA override (default: random 4 chars)")
    agent_encrypted.add_argument("--session-int", help="Encrypted claim session int (default: 0x1869f)")
    agent_encrypted.add_argument("--session-hex-width", type=int, default=10)
    agent_encrypted.add_argument("--channel", type=int, default=0)
    agent_encrypted.add_argument("--stream-type", default="Main")
    agent_encrypted.add_argument("--trans-mode", default="TCP")
    agent_encrypted.add_argument("--combine-mode", default="CONNECT_ALL")
    agent_encrypted.add_argument("--msg-id", help="Encrypted claim msg_id/seq (default: 0x10)")
    agent_encrypted.add_argument("--unk", help="FF01 unk field (default: 0x63)")
    agent_encrypted.add_argument("--cmd", help="FF01 cmd field (default: 0x0585)")
    agent_encrypted.add_argument("--followup-file", help="Decoded 6611 JSON capture to replay c2s frames from after Claim")
    agent_encrypted.add_argument("--followup-cmd", help="Only replay frames with this cmd (for example 0x03e8)")
    agent_encrypted.add_argument("--followup-max", type=int, default=1)
    agent_encrypted.add_argument("--followup-delay", type=float, default=0.0)
    agent_encrypted.add_argument("--controller-auto", action="store_true", help="After successful login, auto-send the best known first 0x582 controller candidate")
    agent_encrypted.add_argument(
        "--controller-profile",
        default="historical_order_built_queries_dynamic_second582",
        help="Auto-controller profile (default: historical_order_built_queries_dynamic_second582)",
    )
    agent_encrypted.add_argument("--timeout", type=float, default=10)
    agent_encrypted.add_argument("--capture-seconds", type=float, default=5.0)
    agent_encrypted.add_argument("--max-frames", type=int, default=200)
    agent_encrypted.add_argument("--raw", help="Raw deviceListJson/logcat text (optional)")
    agent_encrypted.add_argument("--file", help="Path to deviceListJson/logcat file (optional)")
    agent_encrypted.add_argument("--out", help="Write full JSON result to file")
    agent_encrypted.set_defaults(func=cmd_agent_encrypted_probe)

    build_login = sub.add_parser("build-6611-login", help="Build offline candidate cmd=0x03e8 login frame from claim JSON")
    build_login.add_argument("--device-id", help="Target device serial (must exist in --file/--raw device list)")
    build_login.add_argument("--raw", help="Raw deviceListJson/logcat text")
    build_login.add_argument("--file", help="Path to deviceListJson/logcat file")
    build_login.add_argument("--claim-raw", help="Raw decrypted 0x586 JSON")
    build_login.add_argument("--claim-file", help="Path to decrypted 0x586 JSON file")
    build_login.add_argument("--mode", default="auto", choices=["auto", "token", "password"])
    build_login.add_argument("--username", help="Override login username")
    build_login.add_argument("--password", help="Override device password")
    build_login.add_argument("--admin-token", help="Override AdminToken for TOKEN mode")
    build_login.add_argument("--login-type", default="DVRIP-Web")
    build_login.add_argument("--token-username", help="Override TOKEN-mode UserName (default: generated for DVRIP-FutureHome)")
    build_login.add_argument("--random-a", help="Optional RandomStrA for *_DH variants")
    build_login.add_argument("--random-b", help="Optional RandomStrB for *_DH variants")
    build_login.add_argument("--user-agent", help="Optional User-Agent field inside login JSON")
    build_login.add_argument("--communicate-key", help="Override raw 16-byte AES session key")
    build_login.add_argument("--transport-key", help="Override outer AES login key (default: dashoiahfarqdasr)")
    build_login.add_argument("--msg-type", help="FF01 msg_type (default: 0)")
    build_login.add_argument("--session-int", help="FF01 session_id integer (default: 0)")
    build_login.add_argument("--msg-id", help="FF01 msg_id (default: 0x80)")
    build_login.add_argument("--unk", help="FF01 unk field (default: 0x63)")
    build_login.add_argument("--cmd", help="FF01 cmd (default: 0x03e8)")
    build_login.add_argument("--compare-file", help="Decoded 6611 JSON capture for first matching cmd comparison")
    build_login.add_argument("--out", help="Write sanitized JSON result to file")
    build_login.set_defaults(func=cmd_build_6611_login)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
