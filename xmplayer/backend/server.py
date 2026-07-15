from __future__ import annotations

import argparse
import base64
import json
import sys
import threading
from dataclasses import asdict
from typing import Any

from ..config.loader import load_monitor_config
from ..core.service import (
    CaptureArtifacts,
    MonitorCancelled,
    MonitorCaptureError,
    RecordingItem,
    describe_capture_failure,
    fetch_device_recordings,
    fetch_monitor_messages,
    run_monitor_live_stream,
    run_recording_playback_stream,
)
from ..media.live_hevc import LiveXStreamHevcAssembler


class BackendServer:
    def __init__(self) -> None:
        self.config = load_monitor_config()
        self._write_lock = threading.Lock()
        self._session_lock = threading.Lock()
        self._session_generation = 0
        self._session_stop: threading.Event | None = None
        self._session_thread: threading.Thread | None = None

    def send(self, payload: dict[str, Any]) -> None:
        line = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        with self._write_lock:
            sys.stdout.write(line + '\n')
            sys.stdout.flush()

    def response(self, request_id: Any, *, ok: bool, result: Any = None, error: str = '') -> None:
        payload: dict[str, Any] = {'kind': 'response', 'id': request_id, 'ok': bool(ok)}
        if ok:
            payload['result'] = result
        else:
            payload['error'] = error
        self.send(payload)

    def event(self, name: str, **payload: Any) -> None:
        row = {'kind': 'event', 'name': name}
        row.update(payload)
        self.send(row)

    def run(self) -> int:
        self.event('hello', config=self._config_summary())
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                command = json.loads(line)
            except Exception as exc:
                self.event('error', message=f'bad_json: {exc}')
                continue
            self.handle_command(command)
        self.stop_session()
        return 0

    def handle_command(self, command: dict[str, Any]) -> None:
        request_id = command.get('id')
        cmd = str(command.get('cmd') or '').strip()
        if cmd in {'ping', 'hello'}:
            self.response(request_id, ok=True, result={'status': 'ok', 'config': self._config_summary()})
        elif cmd == 'refresh_recordings':
            self._run_async(request_id, self._refresh_recordings)
        elif cmd == 'refresh_messages':
            self._run_async(request_id, self._refresh_messages)
        elif cmd == 'start_live':
            quality = str(command.get('quality') or self.config.default_quality or 'sd').lower()
            self.start_session(recording=None, quality=quality)
            self.response(request_id, ok=True, result={'started': 'live', 'quality': quality})
        elif cmd == 'start_recording':
            recording = self._recording_from_command(command)
            self.start_session(recording=recording, quality='recording')
            self.response(request_id, ok=True, result={'started': 'recording', 'recording': asdict(recording)})
        elif cmd == 'stop':
            self.stop_session()
            self.response(request_id, ok=True, result={'stopped': True})
        elif cmd == 'shutdown':
            self.stop_session()
            self.response(request_id, ok=True, result={'shutdown': True})
            raise SystemExit(0)
        else:
            self.response(request_id, ok=False, error=f'unknown_command: {cmd}')

    def _run_async(self, request_id: Any, fn) -> None:
        def worker() -> None:
            try:
                self.response(request_id, ok=True, result=fn())
            except Exception as exc:  # noqa: BLE001
                self.response(request_id, ok=False, error=str(exc))

        threading.Thread(target=worker, daemon=True, name=f'xmplayer-backend-{fn.__name__}').start()

    def _config_summary(self) -> dict[str, Any]:
        return {
            'device_id': self.config.device_id,
            'device_name': self.config.device_name,
            'default_quality': self.config.default_quality,
            'playback_fps': self.config.playback_fps,
            'display_mode': self.config.display_mode,
        }

    def _refresh_recordings(self) -> dict[str, Any]:
        recordings, meta = fetch_device_recordings(self.config, timeout=20)
        return {
            'recordings': [asdict(item) for item in recordings],
            'meta': meta,
        }

    def _refresh_messages(self) -> dict[str, Any]:
        messages, meta = fetch_monitor_messages(self.config, timeout=12)
        return {
            'messages': [asdict(item) for item in messages],
            'meta': meta,
        }

    def _recording_from_command(self, command: dict[str, Any]) -> RecordingItem:
        raw = command.get('recording')
        if not isinstance(raw, dict):
            raise ValueError('start_recording requires recording object')
        return RecordingItem(
            title=str(raw.get('title') or ''),
            start_time=str(raw.get('start_time') or ''),
            end_time=str(raw.get('end_time') or ''),
            duration_seconds=int(raw.get('duration_seconds') or 0),
            file_name=str(raw.get('file_name') or ''),
            file_length=int(raw.get('file_length') or 0),
            channel=int(raw.get('channel') or 0),
            raw=raw.get('raw') if isinstance(raw.get('raw'), dict) else None,
        )

    def start_session(self, *, recording: RecordingItem | None, quality: str) -> None:
        self.stop_session()
        stop_event = threading.Event()
        assembler = LiveXStreamHevcAssembler()
        with self._session_lock:
            self._session_generation += 1
            generation = self._session_generation
            self._session_stop = stop_event

        def status_callback(state: str, detail: str) -> None:
            if self._is_current_session(generation):
                self.event('status', state=state, detail=detail)

        def data_callback(payload: bytes, vekey1: str) -> bool:
            if stop_event.is_set() or not self._is_current_session(generation):
                return False
            if vekey1:
                assembler.set_random_str(vekey1)
            video_hevc, audio_g711 = assembler.push_media_payload(payload)
            if video_hevc:
                self.event(
                    'media',
                    stream='video_hevc',
                    generation=generation,
                    payload_b64=base64.b64encode(video_hevc).decode('ascii'),
                )
            if audio_g711:
                self.event(
                    'media',
                    stream='audio_g711_alaw_8k_mono',
                    generation=generation,
                    payload_b64=base64.b64encode(audio_g711).decode('ascii'),
                )
            return bool(video_hevc or audio_g711)

        def worker() -> None:
            try:
                capture: CaptureArtifacts
                if recording is None:
                    capture = run_monitor_live_stream(
                        self.config,
                        quality=quality,
                        stop_event=stop_event,
                        status_callback=status_callback,
                        data_frame_callback=data_callback,
                    )
                else:
                    capture = run_recording_playback_stream(
                        self.config,
                        recording,
                        stop_event=stop_event,
                        status_callback=status_callback,
                        data_frame_callback=data_callback,
                    )
                failure = describe_capture_failure(capture.result)
                if failure:
                    self.event('status', state='No video', detail=failure)
                else:
                    self.event('capture', quality=capture.quality, attempts=capture.attempt_count)
            except MonitorCancelled:
                self.event('status', state='Idle', detail='Stopped')
            except MonitorCaptureError as exc:
                self.event('status', state='Error', detail=str(exc))
            except Exception as exc:  # noqa: BLE001
                self.event('status', state='Error', detail=str(exc))

        thread = threading.Thread(target=worker, daemon=True, name='xmplayer-backend-session')
        with self._session_lock:
            self._session_thread = thread
        thread.start()

    def _is_current_session(self, generation: int) -> bool:
        with self._session_lock:
            return generation == self._session_generation

    def stop_session(self) -> None:
        with self._session_lock:
            self._session_generation += 1
            stop_event = self._session_stop
            thread = self._session_thread
            self._session_stop = None
            self._session_thread = None
        if stop_event is not None:
            stop_event.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        self.event('status', state='Idle', detail='Stopped')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='xmplayer backend JSONL server')
    parser.add_argument('--stdio', action='store_true', help='run JSONL stdio protocol')
    parser.add_argument('--self-test', action='store_true', help='load config and print backend summary')
    args = parser.parse_args(argv)

    server = BackendServer()
    if args.self_test:
        print(json.dumps(server._config_summary(), ensure_ascii=False, indent=2))
        return 0
    if not args.stdio:
        parser.error('--stdio is required unless --self-test is used')
    return server.run()


if __name__ == '__main__':
    raise SystemExit(main())
