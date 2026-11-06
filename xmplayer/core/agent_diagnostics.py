from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote, quote_plus


_SECRET_NAMES = {
    'auth', 'authcode', 'authorization', 'clienttoken', 'session', 'sessionid',
    'serial', 'serialnumber', 'sn', 'devsn', 'deviceid', 'uuid', 'account',
    'username', 'login', 'password', 'passwd', 'pwd', 'keys', 'secret',
    'rps', 'p2p', 'pms', 'dss', 'css', 'tps',
}
_SECRET_ASSIGNMENT = re.compile(
    r'''(?i)(["']?(?:\w*token|randomstr\w*|auth(?:code|orization)?|password|passwd|pwd|'''
    r'''secret|keys|serialnumber|serial|deviceid|uuid|username|account|sessionid)["']?\s*[:=]\s*)'''
    r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\[[^\]]*\]|[^\s,;}\]]+)'''
)


def _json_type(value: Any) -> str:
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, str):
        return 'string'
    if isinstance(value, dict):
        return 'object'
    if isinstance(value, list):
        return 'array'
    if isinstance(value, (int, float)):
        return 'number'
    return type(value).__name__


def _secret_values(value: Any) -> set[str]:
    values: set[str] = set()

    def collect(item: Any, sensitive: bool = False) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                name = re.sub(r'[^a-z0-9]', '', str(key).lower())
                collect(child, sensitive or name in _SECRET_NAMES or 'randomstr' in name
                        or name.endswith(('token', 'password', 'secret')))
        elif isinstance(item, list):
            for child in item:
                collect(child, sensitive)
        elif sensitive and item is not None and not isinstance(item, bool):
            text = str(item)
            if text and (isinstance(item, str) or len(text) >= 4):
                values.add(text)

    collect(value)
    return values


def _safe_text(value: Any, secrets: set[str], limit: int = 180, *, mask_opaque: bool = True) -> str:
    if value is None:
        return ''
    if isinstance(value, (dict, list)):
        return f'[{_json_type(value)}]'
    text = str(value)
    # ErrorString may echo a request or a key. Redact before shortening it,
    # including JSON-escaped and URL-encoded forms of the known secrets.
    variants = set(secrets)
    for secret in secrets:
        variants.update((json.dumps(secret, ensure_ascii=False)[1:-1],
                         json.dumps(secret, ensure_ascii=True)[1:-1],
                         quote(secret, safe=''), quote_plus(secret, safe='')))
    pattern = '|'.join(re.escape(secret) for secret in sorted(variants, key=len, reverse=True) if secret)
    if pattern:
        text = re.sub(pattern, '[redacted]', text)
    text = _SECRET_ASSIGNMENT.sub(r'\1[redacted]', text)
    if mask_opaque:
        text = re.sub(r'[A-Za-z0-9_+/=-]{24,}', '[redacted]', text)
    text = ' '.join(text.split())
    return text if len(text) <= limit else text[:limit - 3] + '...'


def summarize_agent_response(
    payload: Any, *, request_payload: Any = None, transport_error: Any = None,
) -> dict[str, Any]:
    """Allowlisted metadata only; never include response bodies or key values."""
    secrets = _secret_values(payload) | _secret_values(request_payload)
    root = payload if isinstance(payload, dict) else {}
    agent_value = root.get('AgentProtocol')
    agent = agent_value if isinstance(agent_value, dict) else {}
    header_value, body_value = agent.get('Header'), agent.get('Body')
    header = header_value if isinstance(header_value, dict) else {}
    body = body_value if isinstance(body_value, dict) else {}

    def fields(value: Any) -> list[str]:
        if not isinstance(value, dict):
            return []
        names = [_safe_text(key, secrets, 64, mask_opaque=False) for key in list(value)[:32]]
        if len(value) > 32:
            names.append(f'... (+{len(value) - 32} fields)')
        return names

    random_value = body.get('RandomStr')
    return {
        'message_type': _safe_text(header.get('MessageType'), secrets, mask_opaque=False),
        'error_num': _safe_text(header.get('ErrorNum'), secrets),
        'error_string': _safe_text(header.get('ErrorString'), secrets),
        'protocol_mode': _safe_text(body.get('ProtocolMode'), secrets),
        'transport_error': _safe_text(transport_error, secrets),
        'response_type': _json_type(payload),
        'agent_type': _json_type(agent_value) if 'AgentProtocol' in root else 'missing',
        'header_type': _json_type(header_value) if 'Header' in agent else 'missing',
        'body_type': _json_type(body_value) if 'Body' in agent else 'missing',
        'fields': {'root': fields(root), 'agent': fields(agent),
                   'header': fields(header), 'body': fields(body)},
        'random_str': {
            'present': 'RandomStr' in body,
            'type': _json_type(random_value) if 'RandomStr' in body else 'missing',
            'length': len(random_value) if isinstance(random_value, (str, list, dict)) else None,
        },
    }
