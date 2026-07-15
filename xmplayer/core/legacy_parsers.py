from __future__ import annotations

import base64
import datetime as dt
import html
import json
import re
from dataclasses import dataclass
from typing import Any


ACCESS_TOKEN_RE = re.compile(r"(?:^|&&)accessToken=([^&]+)")
URL_RE = re.compile(r"(?:rtsp|rtsps|http|https|ws|wss)://[^\s\"'<>]+", re.IGNORECASE)


def parse_login_params(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not raw:
        return out
    for text in _candidate_texts(raw):
        if "&&" not in text and "accessToken=" not in text and "refreshToken=" not in text:
            continue
        for chunk in text.strip().split("&&"):
            if not chunk or "=" not in chunk:
                continue
            key, value = chunk.split("=", 1)
            key = key.strip().lstrip("\ufeff")
            value = value.strip()
            if not key or not value:
                continue
            if any(mark in key for mark in "<>\r\n\t "):
                continue
            if key not in out:
                out[key] = value
    return out


def extract_access_token(raw: str) -> str:
    if not raw:
        return ""
    for text in _candidate_texts(raw):
        match = ACCESS_TOKEN_RE.search(text)
        if match:
            return match.group(1).strip()
    return ""


def extract_default_region_config(raw: str) -> dict[str, Any]:
    if not raw:
        return {}
    for text in _candidate_texts(raw):
        if '"defaultCountry"' not in text and '"regionUrl"' not in text:
            continue
        try:
            parsed = json.loads(text)
        except Exception:
            continue
        if not isinstance(parsed, dict):
            continue
        default_country = parsed.get("defaultCountry")
        if isinstance(default_country, dict):
            return default_country
    return {}


def extract_default_jvss_url(raw: str) -> str:
    region = extract_default_region_config(raw)
    value = region.get("jvssUrl") if isinstance(region, dict) else ""
    return str(value or "").strip()


def _b64url_decode(value: str) -> bytes:
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + pad).encode("ascii", errors="ignore"))


def decode_jwt_no_verify(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = _b64url_decode(parts[1]).decode("utf-8")
        return json.loads(payload)
    except Exception:
        return {}


def jwt_expiry_utc(token: str) -> str:
    payload = decode_jwt_no_verify(token)
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return ""
    return dt.datetime.utcfromtimestamp(exp).strftime("%Y-%m-%d %H:%M:%S UTC")


def _decode_ascii_array(values: Any) -> str:
    if not isinstance(values, list):
        return ""


STRING_VALUE_RE = re.compile(r"<string\b[^>]*>(.*?)</string>", re.DOTALL | re.IGNORECASE)
STRING_NAMED_VALUE_RE = re.compile(r"<string\b[^>]*name=\"([^\"]+)\"[^>]*>(.*?)</string>", re.DOTALL | re.IGNORECASE)
BOOLEAN_NAMED_VALUE_RE = re.compile(r"<boolean\b[^>]*name=\"([^\"]+)\"[^>]*value=\"([^\"]+)\"[^>]*/?>", re.IGNORECASE)


def _candidate_texts(raw: str) -> list[str]:
    if not raw:
        return []
    values: list[str] = []
    for item in (raw, html.unescape(raw)):
        if not item or item in values:
            continue
        values.append(item)
    extracted: list[str] = []
    for item in list(values):
        for match in STRING_VALUE_RE.findall(item):
            unescaped = html.unescape(match)
            if unescaped and unescaped not in values and unescaped not in extracted:
                extracted.append(unescaped)
    values.extend(extracted)
    return values
    cleaned = []
    for v in values:
        if not isinstance(v, int):
            continue
        if v == 0:
            break
        cleaned.append(v & 0xFF)
    if not cleaned:
        return ""
    try:
        return bytes(cleaned).decode("ascii", errors="ignore")
    except Exception:
        return ""


@dataclass
class DeviceCandidate:
    dev_id: str
    nickname: str
    online: bool
    share_auth_token: str
    admin_token: str
    username: str
    password: str
    channel_count: int
    port: str
    pms: str
    rps: str
    dss: str
    tps: str
    css: str
    p2p: str
    support_rps_video: bool = False
    idr_auto_wakeup: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "dev_id": self.dev_id,
            "nickname": self.nickname,
            "online": self.online,
            "share_auth_token": self.share_auth_token,
            "admin_token": self.admin_token,
            "username": self.username,
            "password": self.password,
            "channel_count": self.channel_count,
            "port": self.port,
            "pms": self.pms,
            "rps": self.rps,
            "dss": self.dss,
            "tps": self.tps,
            "css": self.css,
            "p2p": self.p2p,
            "support_rps_video": self.support_rps_video,
            "idr_auto_wakeup": self.idr_auto_wakeup,
        }


def _extract_named_string_values(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not text:
        return out
    for name, value in STRING_NAMED_VALUE_RE.findall(text):
        key = str(name or "").strip()
        if not key or key in out:
            continue
        out[key] = html.unescape(value or "")
    return out


def _extract_named_boolean_values(text: str) -> dict[str, bool]:
    out: dict[str, bool] = {}
    if not text:
        return out
    for name, value in BOOLEAN_NAMED_VALUE_RE.findall(text):
        key = str(name or "").strip()
        if not key or key in out:
            continue
        out[key] = str(value or "").strip().lower() == "true"
    return out


def _extract_support_rps_video_flags(text: str) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for name, raw_value in _extract_named_string_values(text).items():
        if not name.startswith("dev_system_function"):
            continue
        dev_id = name.removeprefix("dev_system_function").strip()
        if not dev_id:
            continue
        try:
            parsed = json.loads(raw_value)
        except Exception:
            continue
        support = (((parsed.get("SystemFunction") or {}).get("OtherFunction") or {}).get("SupportRPSVideo"))
        out[dev_id] = bool(support)
    return out


def _extract_idr_auto_wakeup_flags(text: str) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for name, value in _extract_named_boolean_values(text).items():
        if not name.startswith("idr_dev_auto_wakeup"):
            continue
        dev_id = name.removeprefix("idr_dev_auto_wakeup").strip()
        if not dev_id:
            continue
        out[dev_id] = bool(value)
    return out


def _normalize_device(
    raw: dict[str, Any],
    *,
    support_rps_video: bool = False,
    idr_auto_wakeup: bool = False,
) -> DeviceCandidate:
    shared = raw.get("otherShareDevUserBean") or {}
    device_token = shared.get("deviceToken") or {}
    username = shared.get("username") or _decode_ascii_array(raw.get("st_4_loginName"))
    password = shared.get("password") or _decode_ascii_array(raw.get("st_5_loginPsw"))
    return DeviceCandidate(
        dev_id=str(raw.get("devId") or shared.get("devId") or "").strip(),
        nickname=str(shared.get("nickname") or raw.get("devName") or "").strip(),
        online=bool(raw.get("isOnline")),
        share_auth_token=str(shared.get("shareAuthToken") or "").strip(),
        admin_token=str(device_token.get("AdminToken") or "").strip(),
        username=str(username or "").strip(),
        password=str(password or "").strip(),
        channel_count=int(raw.get("chnCount") or 0),
        port=str(shared.get("port") or raw.get("port") or "").strip(),
        pms=str(shared.get("pms") or "").strip(),
        rps=str(shared.get("rps") or "").strip(),
        dss=str(shared.get("dss") or "").strip(),
        tps=str(shared.get("tps") or "").strip(),
        css=str(shared.get("css") or "").strip(),
        p2p=str(shared.get("p2P") or shared.get("p2p") or "").strip(),
        support_rps_video=bool(support_rps_video),
        idr_auto_wakeup=bool(idr_auto_wakeup),
    )


def extract_device_list_json(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    candidates: list[list[dict[str, Any]]] = []
    for candidate_text in _candidate_texts(text):
        for idx, ch in enumerate(candidate_text):
            if ch != "[":
                continue
            fragment = candidate_text[idx:]
            try:
                parsed, _ = decoder.raw_decode(fragment)
            except Exception:
                continue
            if not isinstance(parsed, list) or not parsed:
                continue
            if not isinstance(parsed[0], dict):
                continue
            if any(k in parsed[0] for k in ("devId", "otherShareDevUserBean", "isOnline")):
                candidates.append(parsed)
    if not candidates:
        return []
    # Prefer longest list found.
    return max(candidates, key=len)


def parse_devices_from_text(text: str) -> list[DeviceCandidate]:
    support_rps_flags = _extract_support_rps_video_flags(text)
    idr_auto_wakeup_flags = _extract_idr_auto_wakeup_flags(text)
    normalized: list[DeviceCandidate] = []
    for item in extract_device_list_json(text):
        if not isinstance(item, dict):
            continue
        dev_id = str(item.get("devId") or (item.get("otherShareDevUserBean") or {}).get("devId") or "").strip()
        cand = _normalize_device(
            item,
            support_rps_video=support_rps_flags.get(dev_id, False),
            idr_auto_wakeup=idr_auto_wakeup_flags.get(dev_id, False),
        )
        if cand.dev_id:
            normalized.append(cand)
    return normalized


def _walk_strings(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for value in obj.values():
            out.extend(_walk_strings(value))
    elif isinstance(obj, list):
        for value in obj:
            out.extend(_walk_strings(value))
    return out


def extract_possible_stream_urls(obj: Any) -> list[str]:
    found: set[str] = set()
    for value in _walk_strings(obj):
        for match in URL_RE.findall(value):
            found.add(match)
    return sorted(found)


def mask_secret(value: str, keep_head: int = 6, keep_tail: int = 4) -> str:
    if not value:
        return value
    if len(value) <= keep_head + keep_tail:
        return "*" * len(value)
    return f"{value[:keep_head]}...{value[-keep_tail:]}"
