from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import List


def _string_to_utf8_bytes(value: str) -> List[int]:
    return list(value.encode("utf-8"))


def _change_bytes(source_text: str, move_card: int) -> List[int]:
    values = _string_to_utf8_bytes(source_text)
    length = len(values)
    for idx in range(length):
        reverse_idx = length - (idx + 1)
        left = values[idx]
        right = values[reverse_idx]
        if move_card > 0 and (idx % move_card) > ((length - idx) % move_card):
            chosen = left
        else:
            chosen = right
        values[idx] = right
        values[reverse_idx] = chosen
    return values


def _merge_bytes(first: List[int], second: List[int]) -> List[int]:
    merged = [0] * (len(first) * 2)
    size = len(first)
    for idx in range(size):
        merged[idx] = first[idx]
        merged[(size * 2) - 1 - idx] = second[idx]
    return merged


def compute_signature(uuid: str, app_key: str, secret: str, time_millis: str, move_card: int) -> str:
    """
    Port of H5 Signature.getSignature() from module 8237.
    """
    raw = f"{uuid}{app_key}{secret}{time_millis}"
    source = _string_to_utf8_bytes(raw)
    changed = _change_bytes(raw, int(move_card))
    merged = _merge_bytes(source, changed)
    return hashlib.md5(bytes(merged)).hexdigest()


def time_millis_like_h5(now: datetime | None = None) -> str:
    """
    H5 prefixes unix millis with a 7-digit counter-like value.
    Their implementation effectively yields '0000002' + epoch_millis.
    """
    now = now or datetime.utcnow()
    epoch_millis = int(now.timestamp() * 1000)
    return f"0000002{epoch_millis}"


@dataclass(frozen=True)
class SignedHeadersInput:
    uuid: str
    app_key: str
    move_card: int
    secret: str
    time_millis: str | None = None


def build_signed_headers(data: SignedHeadersInput) -> dict[str, str]:
    time_millis = data.time_millis or time_millis_like_h5()
    signature = compute_signature(
        uuid=data.uuid,
        app_key=data.app_key,
        secret=data.secret,
        time_millis=time_millis,
        move_card=int(data.move_card),
    )
    return {
        "Content-Type": "application/json",
        "uuid": data.uuid,
        "appKey": data.app_key,
        "timeMillis": time_millis,
        "signature": signature,
    }
