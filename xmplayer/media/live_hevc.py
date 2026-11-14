from __future__ import annotations

from datetime import datetime, timedelta

from . import xstream_decoder as xd


ANNEXB_PREFIX = b"\x00\x00\x00\x01"
DECRYPT_TYPES = {0xEC, 0xEE, 0xFC, 0xFE}


def _fc_annexb_blob(payload_bytes: bytes) -> bytes:
    fc = xd.parse_fc_payload(payload_bytes)
    blob = bytes((fc or {}).get("blob") or b"")
    return blob if blob.startswith(ANNEXB_PREFIX) else b""


class LiveXStreamHevcAssembler:
    def __init__(self, random_str: str = "", *, track_timestamps: bool = False) -> None:
        self._buffer = bytearray()
        self._random_str = ""
        self._key = None
        self._track_timestamps = track_timestamps
        self.frame_rate: int | None = None
        self.video_codec = 'hevc'
        self.first_video_time: datetime | None = None
        self.video_time: datetime | None = None
        self._gop_time: datetime | None = None
        self._gop_frame = 0
        self.set_random_str(random_str)

    def _track_video_frame(self, frame: bytes, frame_type: int) -> None:
        # DVRIP FC layout: codec, fps, width/8, height/8, packed date, length.
        # Reference: github.com/OpenIPC/python-dvr/blob/master/dvrip.py,
        # reassemble_bin_payload().
        if frame_type == 0xFC:
            self._gop_time = None
            self._gop_frame = 0
            if len(frame) < 16 or frame[4] not in {2, 3} or not 1 <= frame[5] <= 120:
                return
            self.video_codec = 'h264' if frame[4] == 2 else 'hevc'
            self.frame_rate = frame[5]
            packed = int.from_bytes(frame[8:12], 'little')
            try:
                self._gop_time = datetime(
                    2000 + (packed >> 26), (packed >> 22) & 15, (packed >> 17) & 31,
                    (packed >> 12) & 31, (packed >> 6) & 63, packed & 63,
                )
            except ValueError:
                return
        else:
            self._gop_frame += 1
        if self._gop_time is not None and self.frame_rate:
            self.video_time = self._gop_time + timedelta(seconds=self._gop_frame / self.frame_rate)
            if self.first_video_time is None:
                self.first_video_time = self.video_time

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
            video_size = len(video_out)
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
            if self._track_timestamps and len(video_out) > video_size:
                self._track_video_frame(frame, frame_type)
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
