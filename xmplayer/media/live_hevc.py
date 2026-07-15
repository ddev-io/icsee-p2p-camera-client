from __future__ import annotations

from . import xstream_decoder as xd


ANNEXB_PREFIX = b"\x00\x00\x00\x01"
DECRYPT_TYPES = {0xEC, 0xEE, 0xFC, 0xFE}


def _fc_annexb_blob(payload_bytes: bytes) -> bytes:
    fc = xd.parse_fc_payload(payload_bytes)
    blob = bytes((fc or {}).get("blob") or b"")
    return blob if blob.startswith(ANNEXB_PREFIX) else b""


class LiveXStreamHevcAssembler:
    def __init__(self, random_str: str = "") -> None:
        self._buffer = bytearray()
        self._random_str = ""
        self._key = None
        self.set_random_str(random_str)

    def set_random_str(self, random_str: str) -> None:
        normalized = str(random_str or "").strip()
        if normalized == self._random_str:
            return
        self._random_str = normalized
        self._key = xd.build_key(normalized) if normalized else None

    def push_media_payload(self, payload: bytes) -> tuple[bytes, bytes]:
        if not payload:
            return b"", b""
        self._buffer.extend(payload)
        frames, remainder = xd.consume_xstream_frames(bytes(self._buffer))
        self._buffer = bytearray(remainder)
        video_out = bytearray()
        audio_out = bytearray()
        for frame, frame_type, head, plen, _total in frames:
            raw_frame = frame
            raw_payload_bytes = raw_frame[head:head + plen]
            if self._key is not None and frame_type in DECRYPT_TYPES:
                frame = xd.on_video_decrypt(self._key, frame, xd.decrypt_offset_for_type(frame_type, frame))
            payload_bytes = frame[head:head + plen]
            if frame_type == 0xFD:
                if payload_bytes.startswith(ANNEXB_PREFIX):
                    video_out.extend(payload_bytes)
            elif frame_type == 0xFC:
                blob = _fc_annexb_blob(payload_bytes)
                if not blob and raw_payload_bytes != payload_bytes:
                    blob = _fc_annexb_blob(raw_payload_bytes)
                if blob:
                    video_out.extend(blob)
            elif frame_type in {0xEC, 0xED, 0xEE, 0xFE}:
                if payload_bytes.startswith(ANNEXB_PREFIX):
                    video_out.extend(payload_bytes)
            elif frame_type == 0xFA:
                audio_out.extend(payload_bytes)
        return bytes(video_out), bytes(audio_out)

    def push_payload(self, payload: bytes) -> bytes:
        video, _audio = self.push_media_payload(payload)
        return video


class LiveXStreamGopAssembler:
    def __init__(self, random_str: str = "") -> None:
        self._buffer = bytearray()
        self._random_str = ""
        self._key = None
        self._current_gop = bytearray()
        self._have_current_fc = False
        self._media_activity = False
        self.set_random_str(random_str)

    def set_random_str(self, random_str: str) -> None:
        normalized = str(random_str or "").strip()
        if normalized == self._random_str:
            return
        self._random_str = normalized
        self._key = xd.build_key(normalized) if normalized else None

    def _append_video_unit(self, out_segments: list[bytes], frame_type: int, payload_bytes: bytes) -> None:
        if frame_type == 0xFC:
            blob = _fc_annexb_blob(payload_bytes)
            if not blob:
                return
            self._media_activity = True
            if self._current_gop:
                out_segments.append(bytes(self._current_gop))
            self._current_gop = bytearray(blob)
            self._have_current_fc = True
            return
        if frame_type in {0xFD, 0xEC, 0xED, 0xEE, 0xFE}:
            if not self._have_current_fc:
                return
            if payload_bytes.startswith(b"\x00\x00\x00\x01"):
                self._media_activity = True
                self._current_gop.extend(payload_bytes)

    def push_payload(self, payload: bytes) -> list[bytes]:
        if not payload:
            return []
        self._buffer.extend(payload)
        frames, remainder = xd.consume_xstream_frames(bytes(self._buffer))
        self._buffer = bytearray(remainder)
        out_segments: list[bytes] = []
        for frame, frame_type, head, plen, _total in frames:
            raw_frame = frame
            raw_payload_bytes = raw_frame[head:head + plen]
            if self._key is not None and frame_type in DECRYPT_TYPES:
                frame = xd.on_video_decrypt(self._key, frame, xd.decrypt_offset_for_type(frame_type, frame))
            payload_bytes = frame[head:head + plen]
            if frame_type == 0xF9:
                if self._current_gop:
                    out_segments.append(bytes(self._current_gop))
                    self._current_gop = bytearray()
                    self._have_current_fc = False
                continue
            if frame_type == 0xFC and not _fc_annexb_blob(payload_bytes) and raw_payload_bytes != payload_bytes:
                payload_bytes = raw_payload_bytes
            self._append_video_unit(out_segments, frame_type, payload_bytes)
        return out_segments

    def flush(self) -> bytes:
        if not self._current_gop:
            return b""
        chunk = bytes(self._current_gop)
        self._current_gop = bytearray()
        self._have_current_fc = False
        return chunk

    def consume_media_activity(self) -> bool:
        seen = self._media_activity
        self._media_activity = False
        return seen
