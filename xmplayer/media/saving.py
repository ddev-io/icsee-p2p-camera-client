"""Save message originals and camera recordings without resizing video."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from fractions import Fraction
from io import BytesIO
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Callable

from ..config.loader import MonitorConfig
from ..core import service
from .live_hevc import LiveXStreamHevcAssembler


class SaveError(RuntimeError):
    pass


def file_stem(value: str, default: str = 'camera') -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '-', value).strip(' .-')
    return name[:120] or default


def save_message_image(data: bytes, destination: Path, original_format: str) -> None:
    """Keep original bytes when possible; convert only if the user changes format."""
    from PIL import Image

    formats = {'.jpg': 'JPEG', '.jpeg': 'JPEG', '.png': 'PNG', '.webp': 'WEBP',
               '.gif': 'GIF', '.bmp': 'BMP'}
    target_format = formats.get(destination.suffix.lower())
    if target_format is None:
        raise SaveError('Choose a supported image extension: JPG, PNG, WebP, GIF or BMP.')
    with tempfile.TemporaryDirectory(prefix='.xmplayer-image-', dir=destination.parent) as folder:
        temporary = Path(folder) / destination.name
        if target_format == original_format.upper():
            temporary.write_bytes(data)
        else:
            with Image.open(BytesIO(data)) as image:
                if target_format == 'JPEG':
                    image = image.convert('RGB')
                    image.save(temporary, format=target_format, quality=95)
                else:
                    image.save(temporary, format=target_format)
        temporary.replace(destination)


@dataclass(frozen=True)
class SavedRecording:
    path: Path
    video_bytes: int
    has_audio: bool
    warning: str = ''


def _bitstream_frame_rate(ffmpeg_path: str, video_path: Path, codec: str,
                         stop_event: threading.Event) -> Fraction | None:
    """Read optional VUI/VPS timing without requiring a separate ffprobe binary."""
    command = [ffmpeg_path, '-nostdin', '-hide_banner', '-loglevel', 'info',
               '-f', codec, '-i', str(video_path), '-map', '0:v:0', '-c:v', 'copy',
               '-bsf:v', 'trace_headers', '-frames:v', '1', '-f', 'null', '-']
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=log, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        deadline = time.monotonic() + 15
        try:
            while process.poll() is None:
                if stop_event.wait(0.2):
                    raise service.MonitorCancelled('Saving cancelled')
                if time.monotonic() >= deadline:
                    return None
            if process.returncode != 0:
                return None  # Some FFmpeg builds do not include trace_headers.
            log.seek(0)
            text = log.read(2 * 1024 * 1024).decode('utf-8', errors='replace')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    values = {name: int(value) for name, value in re.findall(
        r'\b(vps_num_units_in_tick|vps_time_scale|vui_num_units_in_tick|vui_time_scale|'
        r'num_units_in_tick|time_scale)\s+[^=\r\n]*=\s*(\d+)', text)}
    # FFmpeg's HEVC decoder prefers VPS timing, then VUI timing. H.264 timing
    # counts field intervals, so its frame denominator has an additional two.
    prefixes = ('vps_', 'vui_') if codec == 'hevc' else ('',)
    for prefix in prefixes:
        ticks = values.get(prefix + 'num_units_in_tick', 0)
        scale = values.get(prefix + 'time_scale', 0)
        if ticks and scale:
            rate = Fraction(scale, ticks * (2 if codec == 'h264' else 1))
            if 1 <= rate <= 240:
                return rate
    return None


def save_recording(config: MonitorConfig, recording: service.RecordingItem, destination: Path,
                   *, stop_event: threading.Event,
                   progress: Callable[[float | None, str], None]) -> SavedRecording:
    """Receive the selected time range and remux it to MP4, keeping video intact."""
    if destination.suffix.lower() != '.mp4':
        raise SaveError('Choose an MP4 filename.')
    if not shutil.which(config.ffmpeg_path):
        raise SaveError('FFmpeg is required to save recordings as MP4. Check ffmpeg_path.')
    start = service._parse_recording_time(recording.start_time)
    end = service._parse_recording_time(service._recording_end_time(recording))
    if start is None or end is None or end <= start:
        raise SaveError('The camera did not provide a valid recording time range.')
    duration = (end - start).total_seconds()
    assembler = LiveXStreamHevcAssembler(track_timestamps=True)
    transport_stop = threading.Event()
    watchdog_stop = threading.Event()
    deadline = time.monotonic() + max(180.0, duration * 3 + 120)
    last_media_at = 0.0
    covered_at = 0.0
    video_bytes = 0
    received_bytes = 0
    # OPFileQuery FileLength is a size hint in KB. ByTime playback can differ
    # from the on-disk file, so byte progress is approximate, never an EOF test.
    expected_bytes = max(int(recording.file_length or 0), 0) * 1024
    last_progress_at = 0.0
    callback_error: Exception | None = None
    timeout_reason = ''
    deadline_reached = False

    def watchdog() -> None:
        nonlocal timeout_reason, deadline_reached
        while not watchdog_stop.wait(0.2):
            now = time.monotonic()
            if stop_event.is_set():
                transport_stop.set()
                return
            if covered_at and now - covered_at >= 1:
                transport_stop.set()
                return
            if now >= deadline:
                deadline_reached = True
                timeout_reason = 'The recording download exceeded its time limit. Try saving again.'
                transport_stop.set()
                return
            if last_media_at and now - last_media_at >= 20:
                timeout_reason = 'The camera stopped sending the recording before the end.'
                transport_stop.set()
                return

    with tempfile.TemporaryDirectory(prefix='.xmplayer-recording-', dir=destination.parent) as folder:
        folder_path = Path(folder)
        video_path = folder_path / 'video.bin'
        audio_path = folder_path / 'audio.alaw'
        output_path = folder_path / 'recording.mp4'
        with video_path.open('wb') as video_file, audio_path.open('wb') as audio_file:
            def receive(payload: bytes, key: str) -> bool:
                nonlocal last_media_at, covered_at, video_bytes, received_bytes, last_progress_at, callback_error
                if stop_event.is_set() or transport_stop.is_set():
                    return False
                try:
                    received_bytes += len(payload)
                    if key:
                        assembler.set_random_str(key)
                    video, audio = assembler.push_media_payload(payload)
                    if video:
                        video_file.write(video)
                        video_bytes += len(video)
                    if audio:
                        audio_file.write(audio)
                    now = time.monotonic()
                    if video or audio:
                        last_media_at = now
                    media_time = assembler.video_time
                    if received_bytes and (last_progress_at == 0 or now - last_progress_at >= 0.4):
                        received_mb = received_bytes / 1048576
                        if media_time is not None:
                            percent = min(99.0, max(0.0, (media_time - start).total_seconds() / duration * 100))
                            progress(percent, f'Downloading: {percent:.0f}% ({received_mb:.1f} MB)')
                        elif expected_bytes:
                            percent = min(99.0, received_bytes / expected_bytes * 100)
                            progress(percent, f'Downloading: ~{percent:.0f}% '
                                              f'({received_mb:.1f} / {expected_bytes / 1048576:.1f} MB)')
                        else:
                            progress(None, f'Downloading: {received_mb:.1f} MB received')
                        last_progress_at = now
                    if media_time is not None and assembler.frame_rate:
                        # Recording endpoints have one-second precision. Allow
                        # the final frame interval when checking coverage.
                        if media_time >= end - timedelta(seconds=1 / assembler.frame_rate):
                            if not covered_at:
                                covered_at = now
                    return bool(video)
                except Exception as exc:
                    callback_error = exc
                    transport_stop.set()
                    return False

            progress(None, 'Connecting to the camera...')
            watcher = threading.Thread(target=watchdog, daemon=True, name='xmplayer-save-watchdog')
            watcher.start()
            try:
                try:
                    service.run_recording_playback_stream(
                        config, recording, stop_event=transport_stop, attempts=1,
                        capture_seconds=max(180.0, duration * 3 + 120), data_frame_callback=receive,
                        status_callback=lambda _state, detail: progress(None, detail)
                        if not received_bytes else None,
                    )
                except service.MonitorCancelled:
                    if stop_event.is_set():
                        raise
                    # An internal stop can mean the end of the selected time
                    # range or an idle camera. Evaluate received media below.
            finally:
                watchdog_stop.set()
                watcher.join(timeout=1)
        if stop_event.is_set():
            raise service.MonitorCancelled('Saving cancelled')
        if callback_error is not None:
            raise SaveError(f'Could not save the recording: {callback_error}') from callback_error
        if not video_bytes:
            raise SaveError('The camera did not send video for this recording.')
        if deadline_reached:
            raise SaveError(timeout_reason)
        absolute_timing = (assembler.first_video_time is not None
                           and assembler.video_time is not None and assembler.frame_rate is not None)
        warning = ''
        if absolute_timing:
            if assembler.first_video_time > start + timedelta(seconds=1 / assembler.frame_rate) or not covered_at:
                raise SaveError(timeout_reason or 'The recording ended early. No complete MP4 was saved.')
        else:
            # The assembler also supports private/extended XStream headers.
            # Their video is usable even when the classic FC date is absent.
            warning = ('The camera recording timestamps were not recognized. The received video was saved, '
                       'but the full recording time range could not be verified. Check the saved clip.')
        frame_rate = Fraction(assembler.frame_rate) if assembler.frame_rate else None
        if frame_rate is None:
            progress(None, 'Reading video timing...')
            frame_rate = _bitstream_frame_rate(config.ffmpeg_path, video_path, assembler.video_codec, stop_event)
        if frame_rate is None:
            warning += (' ' if warning else '') + (
                'The camera frame rate was unavailable; FFmpeg uses the timing it detects. Check playback speed.')
        progress(99, 'Creating MP4...')
        command = [config.ffmpeg_path, '-nostdin', '-hide_banner', '-loglevel', 'error', '-y',
                   '-fflags', '+genpts']
        if frame_rate is not None:
            command.extend(['-r', str(frame_rate)])
        command.extend(['-f', assembler.video_codec, '-i', str(video_path)])
        has_audio = audio_path.stat().st_size > 0
        if has_audio:
            command.extend(['-f', 'alaw', '-ar', '8000', '-ac', '1', '-i', str(audio_path),
                            '-map', '0:v:0', '-map', '1:a:0', '-c:a', 'aac'])
        command.extend(['-c:v', 'copy'])
        if assembler.video_codec == 'hevc':
            command.extend(['-tag:v', 'hvc1'])
        if absolute_timing:
            saved_duration = (end - assembler.first_video_time).total_seconds()
            command.extend(['-t', str(saved_duration)])
        # Do not trim against an unknown start time or stretch a short capture
        # to the requested duration when the recording dates are unavailable.
        command.extend(['-movflags', '+faststart', str(output_path)])
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=errors, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            mux_deadline = time.monotonic() + max(60, duration / 10)
            try:
                while process.poll() is None:
                    if stop_event.wait(0.2):
                        raise service.MonitorCancelled('Saving cancelled')
                    if time.monotonic() >= mux_deadline:
                        raise SaveError('FFmpeg took too long to create the MP4 file.')
                if process.returncode != 0:
                    errors.seek(0)
                    detail = errors.read(2000).decode('utf-8', errors='replace').strip()
                    raise SaveError(f'FFmpeg could not create MP4. {detail}')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        if stop_event.is_set():
            raise service.MonitorCancelled('Saving cancelled')
        if not output_path.is_file() or not output_path.stat().st_size:
            raise SaveError('FFmpeg did not produce a video file.')
        output_path.replace(destination)
    return SavedRecording(destination, video_bytes, has_audio, warning)
