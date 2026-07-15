from __future__ import annotations

import base64
import json
import queue
import struct
from dataclasses import dataclass
from typing import Any

try:
    from Crypto.Cipher import AES as _AES
except Exception:  # noqa: BLE001
    _AES = None  # type: ignore[assignment]

PTZ_OP_CONTROL_CMD = 0x0578
PTZ_BINARY_CMD = 0x2B09
DEFAULT_PTZ_SPEED = 4
DEFAULT_PTZ_HOLD_SECONDS = 0.65
DEFAULT_PTZ_WIRE_MODE = "opptz"

# Kept for old binary 0x2b09 calibration tools. The working app path is the
# OPPTZControl JSON command below.
PTZ_CODE_ALIASES: dict[str, int] = {
    "up": 4,
    "down": 6,
    "left": 10,
    "right": 8,
}

PTZ_COMMAND_ALIASES: dict[str, str] = {
    "up": "DirectionUp",
    "down": "DirectionDown",
    "left": "DirectionRight",
    "right": "DirectionLeft",
    "directionup": "DirectionUp",
    "directiondown": "DirectionDown",
    "directionleft": "DirectionLeft",
    "directionright": "DirectionRight",
}


@dataclass(frozen=True, slots=True)
class BinaryPtzRequest:
    ptz_code: int
    speed: int = DEFAULT_PTZ_SPEED
    action: int = 1
    delay_before: float = 0.0
    wire_mode: str = "raw"
    label: str = ""


class PtzCommandQueue:
    def __init__(self) -> None:
        self._queue: queue.Queue[Any] = queue.Queue()

    def clear(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                return

    def get_nowait(self) -> Any:
        return self._queue.get_nowait()

    def enqueue(self, request: Any) -> None:
        self._queue.put(request)

    def enqueue_pulse(
        self,
        code: int | str,
        *,
        speed: int = DEFAULT_PTZ_SPEED,
        hold: float = DEFAULT_PTZ_HOLD_SECONDS,
        wire_mode: str = DEFAULT_PTZ_WIRE_MODE,
        label: str = "",
    ) -> int:
        ptz_code = resolve_ptz_code(code)
        clean_speed = max(1, min(int(speed or DEFAULT_PTZ_SPEED), 8))
        clean_hold = max(0.05, min(float(hold or DEFAULT_PTZ_HOLD_SECONDS), 3.0))
        clean_wire_mode = normalize_wire_mode(wire_mode)
        clean_label = label or str(code)
        if clean_wire_mode == "opptz":
            command = resolve_ptz_command(code)
            self.enqueue(
                {
                    "wire_mode": "opptz",
                    "command": command,
                    "preset": 65535,
                    "step": clean_speed,
                    "delay_before": 0.0,
                    "label": clean_label,
                }
            )
            self.enqueue(
                {
                    "wire_mode": "opptz",
                    "command": command,
                    "preset": -1,
                    "step": clean_speed,
                    "delay_before": clean_hold,
                    "label": clean_label,
                }
            )
            return ptz_code
        self.enqueue(
            BinaryPtzRequest(
                ptz_code=ptz_code,
                speed=clean_speed,
                action=1,
                delay_before=0.0,
                wire_mode=clean_wire_mode,
                label=clean_label,
            )
        )
        self.enqueue(
            BinaryPtzRequest(
                ptz_code=ptz_code,
                speed=clean_speed,
                action=0,
                delay_before=clean_hold,
                wire_mode=clean_wire_mode,
                label=clean_label,
            )
        )
        return ptz_code

    def enqueue_stop(
        self,
        code: int | str,
        *,
        speed: int = DEFAULT_PTZ_SPEED,
        wire_mode: str = DEFAULT_PTZ_WIRE_MODE,
        label: str = "",
    ) -> int:
        ptz_code = resolve_ptz_code(code)
        clean_wire_mode = normalize_wire_mode(wire_mode)
        if clean_wire_mode == "opptz":
            self.enqueue(
                {
                    "wire_mode": "opptz",
                    "command": resolve_ptz_command(code),
                    "preset": -1,
                    "step": max(1, min(int(speed or DEFAULT_PTZ_SPEED), 8)),
                    "delay_before": 0.0,
                    "label": label or str(code),
                }
            )
            return ptz_code
        self.enqueue(
            BinaryPtzRequest(
                ptz_code=ptz_code,
                speed=max(1, min(int(speed or DEFAULT_PTZ_SPEED), 8)),
                action=0,
                delay_before=0.0,
                wire_mode=clean_wire_mode,
                label=label or str(code),
            )
        )
        return ptz_code

    def enqueue_stop_all(self, *, speed: int = DEFAULT_PTZ_SPEED, wire_mode: str = "raw") -> int:
        count = 0
        seen: set[int] = set()
        for name in ("up", "down", "left", "right"):
            code = resolve_ptz_code(name)
            if code in seen:
                continue
            seen.add(code)
            self.enqueue_stop(code, speed=speed, wire_mode=wire_mode, label="stop")
            count += 1
        return count


def resolve_ptz_code(value: int | str) -> int:
    if isinstance(value, int):
        return int(value)
    text = str(value or "").strip().lower()
    if not text:
        raise ValueError("PTZ code is empty")
    if text in PTZ_CODE_ALIASES:
        return PTZ_CODE_ALIASES[text]
    command = PTZ_COMMAND_ALIASES.get(text)
    if command:
        for alias, ptz_code in PTZ_CODE_ALIASES.items():
            if PTZ_COMMAND_ALIASES.get(alias) == command:
                return ptz_code
    return int(text, 0)


def resolve_ptz_command(value: int | str) -> str:
    if isinstance(value, int):
        reverse = {4: "DirectionUp", 6: "DirectionDown", 8: "DirectionLeft", 10: "DirectionRight"}
        if int(value) in reverse:
            return reverse[int(value)]
        raise ValueError(f"Unsupported OPPTZ numeric code: {value}")
    text = str(value or "").strip()
    if not text:
        raise ValueError("PTZ command is empty")
    command = PTZ_COMMAND_ALIASES.get(text.lower())
    if command:
        return command
    if text.startswith("Direction"):
        return text
    raise ValueError(f"Unsupported PTZ command: {value}")


def normalize_wire_mode(value: str) -> str:
    mode = str(value or DEFAULT_PTZ_WIRE_MODE).strip().lower().replace("_", "")
    if mode in {"opptz", "opptzcontrol", "json"}:
        return "opptz"
    if mode not in {"raw", "raw-null"}:
        return DEFAULT_PTZ_WIRE_MODE
    return mode


def build_opptz_payload(
    command: str,
    session_id: int,
    *,
    channel: int = 0,
    step: int = DEFAULT_PTZ_SPEED,
    preset: int = -1,
    tour: int = 0,
    pattern: str = "SetBegin",
) -> str:
    parameter = {
        "AUX": {"Number": 0, "Status": "On"},
        "Channel": int(channel),
        "MenuOpts": "Enter",
        "POINT": {"bottom": 0, "left": 0, "right": 0, "top": 0},
        "Pattern": pattern,
        "Preset": int(preset),
        "Step": max(1, min(int(step or DEFAULT_PTZ_SPEED), 8)),
        "Tour": int(tour),
    }
    body = {
        "Name": "OPPTZControl",
        "OPPTZControl": {"Command": resolve_ptz_command(command), "Parameter": parameter},
        "SessionID": f"0x{int(session_id):010x}",
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _aes_cbc_zero_pad_encrypt_base64(raw: bytes, key_text: str) -> str:
    if _AES is None:
        raise RuntimeError("pycryptodome is required for PTZ OPPTZControl encryption")
    key = str(key_text or "").encode("utf-8")
    if len(key) not in {16, 24, 32}:
        raise ValueError(f"invalid PTZ CommunicateKey length: {len(key)}")
    padded = raw + b"\x00" * (-len(raw) % 16)
    cipher = _AES.new(key, _AES.MODE_CBC, iv=b"\x00" * 16)
    return base64.b64encode(cipher.encrypt(padded)).decode("ascii")


def _build_opptz_followup(
    request: dict[str, Any],
    *,
    runtime_session_id: int,
    msg_id: int,
    communicate_key: str,
) -> dict[str, Any]:
    if not communicate_key:
        raise RuntimeError("CommunicateKey is required for OPPTZControl PTZ")
    command = resolve_ptz_command(str(request.get("command") or request.get("direction") or ""))
    preset = int(request.get("preset") if request.get("preset") is not None else -1)
    step = max(1, min(int(request.get("step") or request.get("speed") or DEFAULT_PTZ_SPEED), 8))
    label = str(request.get("label") or command)
    plain_payload = build_opptz_payload(command, int(runtime_session_id), preset=preset, step=step)
    encrypted_b64 = _aes_cbc_zero_pad_encrypt_base64(plain_payload.encode("utf-8"), communicate_key)
    return {
        "msg_type": 0,
        "session_id": int(runtime_session_id),
        "msg_id": int(msg_id),
        "unk": 0,
        "cmd": PTZ_OP_CONTROL_CMD,
        "code": 0,
        "code_endian": "be",
        "payload_text": encrypted_b64,
        "payload_bytes": encrypted_b64.encode("utf-8") + b"\x00",
        "send_phase": "ptz_opptz",
        "controller_profile": "ptz_opptz",
        "plain_payload_text": plain_payload,
        "ptz_code": resolve_ptz_code(command),
        "ptz_speed": step,
        "ptz_action": 1 if preset == 65535 else 0,
        "ptz_wire_mode": "opptz",
        "ptz_command": command,
        "ptz_preset": preset,
        "label": label,
    }


def build_binary_ptz_payload(ptz_code: int, speed: int, action: int) -> bytes:
    return struct.pack("<IIII", int(ptz_code), 0, int(speed), int(action))


def build_binary_ptz_followup(
    request: BinaryPtzRequest | dict[str, Any],
    *,
    runtime_session_id: int,
    msg_id: int,
    communicate_key: str = "",
) -> dict[str, Any]:
    if isinstance(request, dict) and normalize_wire_mode(str(request.get("wire_mode") or "raw")) == "opptz":
        return _build_opptz_followup(
            request,
            runtime_session_id=runtime_session_id,
            msg_id=msg_id,
            communicate_key=communicate_key,
        )
    if isinstance(request, BinaryPtzRequest):
        ptz_code = request.ptz_code
        speed = request.speed
        action = request.action
        wire_mode = request.wire_mode
        label = request.label
    else:
        ptz_code = int(request.get("ptz_code") or request.get("code") or 0)
        speed = int(request.get("speed") or DEFAULT_PTZ_SPEED)
        action = int(request.get("action") or 0)
        wire_mode = normalize_wire_mode(str(request.get("wire_mode") or "raw"))
        label = str(request.get("label") or request.get("direction") or ptz_code)

    raw_payload = build_binary_ptz_payload(ptz_code, speed, action)
    payload = raw_payload + b"\x00" if normalize_wire_mode(wire_mode) == "raw-null" else raw_payload
    return {
        "msg_type": 0,
        "session_id": int(runtime_session_id),
        "msg_id": int(msg_id),
        "unk": 0,
        "cmd": PTZ_BINARY_CMD,
        "code": 0,
        "code_endian": "be",
        "payload_bytes": payload,
        "send_phase": "ptz_binary_2b09",
        "controller_profile": "ptz_binary_2b09",
        "plain_payload_text": (
            f"PTZ_BINARY_2B09 label={label} code={ptz_code} "
            f"speed={speed} action={action} raw={raw_payload.hex()}"
        ),
        "ptz_code": int(ptz_code),
        "ptz_speed": int(speed),
        "ptz_action": int(action),
        "ptz_wire_mode": normalize_wire_mode(wire_mode),
    }
