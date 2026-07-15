from __future__ import annotations

import subprocess
import threading
import time
from typing import Any, Callable


CREATE_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


class FFmpegFrameDecoder:
    def __init__(self, ffmpeg_path: str = 'ffmpeg', *, width: int = 1280, height: int = 720, playback_fps: float = 12.0) -> None:
        self.ffmpeg_path = ffmpeg_path
        self.width = width
        self.height = height
        self.playback_fps = max(float(playback_fps), 1.0)
        self.frame_size = width * height * 3
        self._process: subprocess.Popen[bytes] | None = None

    def stop(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
        except Exception:
            pass
        try:
            if process.stdout:
                process.stdout.close()
        except Exception:
            pass
        try:
            process.terminate()
            process.wait(timeout=1.5)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    def decode_bytes(
        self,
        hevc_bytes: bytes,
        *,
        stop_event: threading.Event | None = None,
        on_frame: Callable[[Any], None],
    ) -> int:
        from PIL import Image

        vf = f'scale=w={self.width}:h={self.height}:force_original_aspect_ratio=decrease,pad={self.width}:{self.height}:(ow-iw)/2:(oh-ih)/2:black'
        cmd = [
            self.ffmpeg_path,
            '-loglevel', 'error',
            '-flags', 'low_delay',
            '-f', 'hevc',
            '-i', 'pipe:0',
            '-vf', vf,
            '-f', 'rawvideo',
            '-pix_fmt', 'rgb24',
            'pipe:1',
        ]
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=self.frame_size * 2,
            creationflags=CREATE_NO_WINDOW,
        )
        self._process = process

        def _writer() -> None:
            try:
                if process.stdin is not None:
                    process.stdin.write(hevc_bytes)
                    process.stdin.flush()
                    process.stdin.close()
            except Exception:
                pass

        writer = threading.Thread(target=_writer, daemon=True)
        writer.start()
        frame_count = 0
        frame_interval = 1.0 / self.playback_fps
        next_frame_at = time.perf_counter()
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                if process.stdout is None:
                    break
                try:
                    chunk = process.stdout.read(self.frame_size)
                except (ValueError, OSError):
                    break
                if not chunk or len(chunk) < self.frame_size:
                    break
                image = Image.frombytes('RGB', (self.width, self.height), chunk)
                now = time.perf_counter()
                wait_seconds = next_frame_at - now
                if wait_seconds > 0:
                    time.sleep(wait_seconds)
                on_frame(image)
                frame_count += 1
                next_frame_at = max(next_frame_at + frame_interval, time.perf_counter())
        finally:
            self.stop()
        return frame_count


class FFmpegStreamDecoder:
    def __init__(self, ffmpeg_path: str = 'ffmpeg', *, width: int = 1280, height: int = 720) -> None:
        self.ffmpeg_path = ffmpeg_path
        self.width = width
        self.height = height
        self.frame_size = width * height * 3
        self._process: subprocess.Popen[bytes] | None = None
        self._reader_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._on_frame: Callable[[Any], None] | None = None

    def start(self, *, on_frame: Callable[[Any], None], output_fps: float | None = None) -> None:
        from PIL import Image

        if self._process is not None:
            return
        _ = output_fps
        self._on_frame = on_frame
        self._stop_event.clear()
        vf = f'scale=w={self.width}:h={self.height}:force_original_aspect_ratio=decrease,pad={self.width}:{self.height}:(ow-iw)/2:(oh-ih)/2:black'
        cmd = [
            self.ffmpeg_path,
            '-loglevel', 'error',
            '-flags', 'low_delay',
            '-f', 'hevc',
            '-i', 'pipe:0',
            '-vf', vf,
            '-f', 'rawvideo',
            '-pix_fmt', 'rgb24',
            'pipe:1',
        ]
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=self.frame_size * 2,
            creationflags=CREATE_NO_WINDOW,
        )
        self._process = process

        def _reader() -> None:
            try:
                while not self._stop_event.is_set():
                    if process.stdout is None:
                        break
                    try:
                        chunk = process.stdout.read(self.frame_size)
                    except (ValueError, OSError):
                        break
                    if not chunk or len(chunk) < self.frame_size:
                        break
                    image = Image.frombytes('RGB', (self.width, self.height), chunk)
                    if self._on_frame is not None:
                        self._on_frame(image)
            finally:
                self.stop()

        self._reader_thread = threading.Thread(target=_reader, daemon=True, name='xmplayer-ffmpeg-reader')
        self._reader_thread.start()

    def write(self, hevc_bytes: bytes) -> bool:
        process = self._process
        if process is None or process.stdin is None or not hevc_bytes or self._stop_event.is_set():
            return False
        try:
            process.stdin.write(hevc_bytes)
            process.stdin.flush()
            return True
        except (ValueError, OSError, BrokenPipeError):
            return False

    def stop(self) -> None:
        process = self._process
        self._process = None
        self._stop_event.set()
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
        except Exception:
            pass
        try:
            if process.stdout:
                process.stdout.close()
        except Exception:
            pass
        try:
            process.terminate()
            process.wait(timeout=1.5)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
