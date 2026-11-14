from __future__ import annotations

from collections import deque
from io import BytesIO
import importlib
import json
import queue
import shutil
import ssl
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any
import urllib.request

from ..config.loader import MonitorConfig, load_monitor_config, validate_connection_credentials
from ..core.service import (
    CaptureArtifacts,
    MonitorCancelled,
    MonitorCaptureError,
    MonitorMessage,
    RecordingItem,
    describe_capture_failure,
    discover_cloud_device_ids,
    fetch_device_recordings,
    fetch_monitor_messages,
    run_monitor_live_stream,
    run_recording_playback_stream,
)
from ..core.ptz import PtzCommandQueue
from ..media.ffmpeg_player import FFmpegStreamDecoder
from ..media.audio_player import G711AudioPlayer
from ..media.live_hevc import LiveXStreamHevcAssembler


def _load_palette(config: MonitorConfig) -> dict[str, str]:
    palette_path = config.project_root / 'xmplayer' / 'assets' / 'monitor_palette.json'
    try:
        return json.loads(palette_path.read_text(encoding='utf-8'))
    except Exception:
        return {
            'bg': '#0d1117',
            'panel': '#161b22',
            'surface': '#05070a',
            'border': '#2b3440',
            'text': '#e6edf3',
            'muted': '#8b949e',
            'accent': '#2ea043',
            'warn': '#d29922',
            'danger': '#f85149',
            'badge_sd': '#1f6feb',
            'badge_hd': '#2ea043',
        }


def _blend_hex_color(foreground: str, background: str, alpha: float) -> str:
    try:
        fg = str(foreground or '').strip().lstrip('#')
        bg = str(background or '').strip().lstrip('#')
        if len(fg) != 6 or len(bg) != 6:
            return foreground
        alpha = min(max(float(alpha), 0.0), 1.0)
        channels = []
        for index in range(0, 6, 2):
            fg_value = int(fg[index:index + 2], 16)
            bg_value = int(bg[index:index + 2], 16)
            channels.append(round(fg_value * alpha + bg_value * (1.0 - alpha)))
        return '#{:02x}{:02x}{:02x}'.format(*channels)
    except Exception:
        return foreground


def _startup_issues(config: MonitorConfig) -> list[str]:
    issues: list[str] = []
    try:
        importlib.import_module('tkinter')
    except Exception as exc:
        issues.append(f'tkinter is unavailable: {exc}')
    try:
        importlib.import_module('PIL.ImageTk')
    except Exception as exc:
        issues.append(f'Pillow ImageTk bridge is unavailable: {exc}')
    login_issue = validate_connection_credentials(config)
    if login_issue:
        issues.append(login_issue)
    return issues


def _show_startup_error(message: str) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror('xmplayer startup error', message)
        root.destroy()
    except Exception:
        print(message)




def _save_device_id(config_path: Path, device_id: str) -> None:
    clean_device_id = str(device_id or '').strip()
    if not clean_device_id:
        raise ValueError('device ID is empty')
    raw = json.loads(config_path.read_text(encoding='utf-8-sig'))
    if not isinstance(raw, dict):
        raise ValueError('desktop_monitor.json must contain an object')
    raw['device_id'] = clean_device_id
    local_config_path = config_path.with_name('desktop_monitor.local.json')
    temporary_path = local_config_path.with_suffix(local_config_path.suffix + '.tmp')
    try:
        temporary_path.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        temporary_path.replace(local_config_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _fit_size(src_w: int, src_h: int, box_w: int, box_h: int) -> tuple[int, int]:
    if src_w <= 0 or src_h <= 0 or box_w <= 0 or box_h <= 0:
        return max(box_w, 1), max(box_h, 1)
    scale = min(box_w / src_w, box_h / src_h)
    return max(int(src_w * scale), 1), max(int(src_h * scale), 1)


def _stacked_split_view(pil_image, image_factory):
    src_w, src_h = pil_image.size
    if src_w < 4 or src_h < 4:
        return pil_image
    tile_h = max(src_h // 2, 1)
    tile_w = min(src_w, max(int(round(tile_h * 16 / 9)), 1))
    left = max((src_w - tile_w) // 2, 0)
    right = min(left + tile_w, src_w)
    upper = pil_image.crop((left, 0, right, tile_h))
    lower = pil_image.crop((left, src_h - tile_h, right, src_h))
    out = image_factory.new(pil_image.mode, (upper.width + lower.width, tile_h), 0)
    out.paste(upper, (0, 0))
    out.paste(lower, (upper.width, 0))
    return out


def _summarize_second_probe(result: dict[str, Any]) -> tuple[str, int]:
    runs = result.get('plain_handoff_runs') or []
    best_status = ''
    best_data_frames = 0
    for run in runs:
        probe = run.get('probe') or {}
        frames = probe.get('frames') or {}
        best_data_frames = max(best_data_frames, len(frames.get('data_frames') or []))
        status = str(probe.get('status') or '')
        if status == 'ok':
            best_status = 'ok'
        elif not best_status and status:
            best_status = status
    return best_status, best_data_frames

def _run_gui_session() -> int:
    try:
        config = load_monitor_config()
    except Exception as exc:
        _show_startup_error(f'Failed to load desktop_monitor.json\n\n{exc}')
        return 1

    login_issue = validate_connection_credentials(config)
    if login_issue:
        try:
            from .connection import prompt_for_connection
            saved_path = prompt_for_connection(config)
        except Exception as exc:
            _show_startup_error(f'Unable to show the connection window\n\n{exc}')
            return 1
        if not saved_path:
            return 1
        try:
            config = load_monitor_config(saved_path)
        except Exception as exc:
            _show_startup_error(f'Failed to load desktop_monitor.json\n\n{exc}')
            return 1

    if config.connection_mode == 'account' and (login_issue or not config.device_id):
        try:
            device_ids = discover_cloud_device_ids(config)
            _save_device_id(config.config_path, device_ids[0])
            config = load_monitor_config()
        except Exception as exc:
            _show_startup_error(f'Unable to load a camera from this account\n\n{exc}')
            return 1

    issues = _startup_issues(config)
    if issues:
        _show_startup_error('xmplayer cannot start yet\n\n' + '\n'.join(f'- {item}' for item in issues))
        return 1

    import tkinter as tk
    from PIL import Image, ImageTk
    from .wifi import CameraWifiDialog

    palette = _load_palette(config)

    class MonitorApp(tk.Tk):
        def __init__(self) -> None:
            super().__init__()
            self.config_data = config
            self.palette = palette
            self.Image = Image
            self.ImageTk = ImageTk
            self.title(f"xmplayer - {config.device_name}")
            self.geometry(f"{config.window.width}x{config.window.height}")
            self.configure(bg=self.palette['bg'])
            if not config.window.start_fullscreen:
                try:
                    self.state('zoomed')
                except Exception:
                    pass

            self._ui_queue: queue.Queue[tuple[str, Any, Any]] = queue.Queue()
            self._worker: threading.Thread | None = None
            self._recordings_worker: threading.Thread | None = None
            self._messages_worker: threading.Thread | None = None
            self._stop_event = threading.Event()
            self._decoder: FFmpegStreamDecoder | None = None
            self._audio_player: G711AudioPlayer | None = None
            self._last_source_image = None
            self._last_pil_image = None
            self._last_tk_image = None
            self._pending_frames: deque[Any] = deque()
            self._frame_interval_ms = max(int(1000 / max(config.playback_fps, 1.0)), 16)
            self._session_idle_reconnect_seconds = max(2.0, 24.0 / max(config.playback_fps, 1.0))
            self._poll_after_id: str | None = None
            self._playback_after_id: str | None = None
            self._restart_after_id: str | None = None
            self._restart_pending = False
            self._stop_pending = False
            self._session_generation = 0
            self._recordings_generation = 0
            self._messages_generation = 0
            self._button_widgets: dict[str, Any] = {}
            self._section_buttons: dict[str, Any] = {}
            self._section_pages: dict[str, Any] = {}
            self._active_section = 'live'
            self._closing = False
            self._restart_app = False
            self._fullscreen = False
            self._fullscreen_after_id: str | None = None
            self._video_resize_after_id: str | None = None
            self._windowed_state = 'normal'
            self._windowed_geometry = ''
            self._current_quality = config.default_quality
            self._video_layout = 'horizontal' if config.display_mode == 'stacked_split' else 'vertical'
            self._current_recording: RecordingItem | None = None
            self._status = 'Idle'
            self._detail = 'Ready to start'
            self._capture_artifacts: CaptureArtifacts | None = None
            self._recordings_loaded = False
            self._messages_loaded = False
            self._startup_progress_value = 0.0
            self._startup_progress_display_value = 0.0
            self._startup_progress_pulse = 0.0
            self._startup_progress_after_id: str | None = None
            self._message_thumb_images: list[Any] = []
            self._message_thumb_hosts: dict[int, Any] = {}
            self._message_thumb_refs: dict[int, list[Any]] = {}
            self._message_full_images: dict[tuple[int, int], Any] = {}
            self._message_viewer: Any | None = None
            self._message_viewer_key: tuple[int, int] | None = None
            self._message_viewer_photo: Any | None = None
            self._wifi_dialog: CameraWifiDialog | None = None
            self._message_viewer_source: Any | None = None
            self._message_viewer_label: Any | None = None
            self._message_viewer_zoom = 1.0
            self._message_viewer_zoom_var: Any | None = None
            self._ptz_queue = PtzCommandQueue()
            self._ptz_panel_visible = False
            self._payload_activity_seen = False
            self._video_material_seen = False
            self._rendered_frame_count = 0
            self._recording_playback_started_at = 0.0
            self._playback_banner_packed = False

            self._build_ui()
            self.protocol('WM_DELETE_WINDOW', self._on_close)
            self.bind('<Escape>', self._on_escape)
            self._poll_after_id = self.after(80, self._poll_queue)
            self._playback_after_id = self.after(self._frame_interval_ms, self._playback_tick)
            self._update_quality_badge()
            self._set_state('Idle', 'Ready to start')
            if config.window.start_fullscreen:
                self.after_idle(self._toggle_fullscreen)

        def _build_ui(self) -> None:
            header = tk.Frame(self, bg=self.palette['panel'], bd=0, highlightthickness=1, highlightbackground=self.palette['border'])
            self.header = header
            header.pack(fill='x', padx=18, pady=(18, 10))
            left = tk.Frame(header, bg=self.palette['panel'])
            left.pack(side='left', fill='x', expand=True, padx=16, pady=14)
            tk.Label(left, text=self.config_data.device_name, fg=self.palette['text'], bg=self.palette['panel'], font=('Segoe UI Semibold', 18)).pack(anchor='w')
            mode_row = tk.Frame(left, bg=self.palette['panel'])
            mode_row.pack(anchor='w', fill='x', pady=(8, 0))
            self.mode_var = tk.StringVar(value='LIVE')
            self.mode_badge = tk.Label(
                mode_row,
                textvariable=self.mode_var,
                fg='white',
                bg=self.palette['accent'],
                font=('Segoe UI Semibold', 9),
                padx=10,
                pady=4,
            )
            self.mode_badge.pack(side='left')
            self.mode_detail_var = tk.StringVar(value='Camera live stream')
            self.mode_detail_label = tk.Label(
                mode_row,
                textvariable=self.mode_detail_var,
                fg=self.palette['muted'],
                bg=self.palette['panel'],
                font=('Segoe UI', 10),
            )
            self.mode_detail_label.pack(side='left', padx=(10, 0))
            self.status_var = tk.StringVar(value='Idle')
            self.detail_var = tk.StringVar(value='Ready to start')
            self.status_label = tk.Label(left, textvariable=self.status_var, fg=self.palette['accent'], bg=self.palette['panel'], font=('Segoe UI', 11, 'bold'))
            self.status_label.pack(anchor='w', pady=(6, 0))
            self.detail_label = tk.Label(left, textvariable=self.detail_var, fg=self.palette['muted'], bg=self.palette['panel'], font=('Segoe UI', 10))
            self.detail_label.pack(anchor='w')

            right = tk.Frame(header, bg=self.palette['panel'])
            right.pack(side='right', padx=16, pady=14)
            self.quality_var = tk.StringVar(value=self._current_quality.upper())
            self.quality_badge = tk.Label(right, textvariable=self.quality_var, fg='white', bg=self.palette['badge_sd'], font=('Segoe UI', 10, 'bold'), padx=12, pady=6)
            self.quality_badge.pack(anchor='e')
            tk.Label(right, text='Cloud ID' if config.connection_mode == 'cloud_id' else 'App account',
                     fg=self.palette['muted'], bg=self.palette['panel'],
                     font=('Segoe UI', 9)).pack(anchor='e', pady=(6, 0))

            tabbar = tk.Frame(self, bg=self.palette['bg'])
            self.tabbar = tabbar
            tabbar.pack(fill='x', padx=18, pady=(0, 10))
            for key, label in (
                ('live', 'Live'),
                ('recordings', 'Recordings'),
                ('messages', 'Messages'),
            ):
                btn = tk.Button(
                    tabbar,
                    text=label,
                    command=lambda name=key: self._show_section(name),
                    relief='flat',
                    bd=0,
                    padx=20,
                    pady=10,
                    bg=self.palette['panel'],
                    fg=self.palette['muted'],
                    activebackground=self.palette['border'],
                    activeforeground=self.palette['text'],
                    font=('Segoe UI Semibold', 11),
                )
                btn.pack(side='left', padx=(0, 8))
                self._section_buttons[key] = btn
                if key == 'messages' and config.connection_mode == 'cloud_id':
                    btn.configure(state='disabled')

            connection_button = tk.Button(
                tabbar, text='Connection...', command=self._change_connection,
                relief='flat', bd=0, padx=16, pady=10,
                bg=self.palette['panel'], fg=self.palette['text'],
                activebackground=self.palette['border'], activeforeground=self.palette['text'],
                font=('Segoe UI Semibold', 11))
            connection_button.pack(side='right', padx=(8, 0))
            self._button_widgets['Connection'] = connection_button

            tk.Button(
                tabbar, text='Camera Wi-Fi', command=self._open_wifi_settings,
                relief='flat', bd=0, padx=20, pady=10,
                bg=self.palette['panel'], fg=self.palette['text'],
                activebackground=self.palette['border'], activeforeground=self.palette['text'],
                font=('Segoe UI Semibold', 11),
            ).pack(side='right')

            self.section_host = tk.Frame(self, bg=self.palette['bg'])
            self.section_host.pack(fill='both', expand=True, padx=18, pady=(0, 18))

            live_page = tk.Frame(self.section_host, bg=self.palette['bg'])
            self._section_pages['live'] = live_page

            self.playback_banner = tk.Frame(live_page, bg='#21190c', highlightthickness=1, highlightbackground=self.palette['warn'])
            self.playback_banner_var = tk.StringVar(value='')
            self.playback_banner_label = tk.Label(
                self.playback_banner,
                textvariable=self.playback_banner_var,
                fg=self.palette['text'],
                bg='#21190c',
                font=('Segoe UI Semibold', 11),
                anchor='w',
                padx=14,
                pady=10,
            )
            self.playback_banner_label.pack(fill='x')

            self.video_frame = tk.Frame(live_page, bg=self.palette['surface'], highlightthickness=1, highlightbackground=self.palette['border'])
            self.video_frame.pack(fill='both', expand=True, pady=(0, 10))
            self.video_label = tk.Label(self.video_frame, bg=self.palette['surface'], bd=0, highlightthickness=0)
            self.video_label.pack(fill='both', expand=True)
            self.video_frame.bind('<Configure>', self._schedule_video_redraw)
            self.video_mode_var = tk.StringVar(value='LIVE')
            self.video_mode_badge = tk.Label(
                self.video_frame,
                textvariable=self.video_mode_var,
                fg='white',
                bg=self.palette['accent'],
                font=('Segoe UI Semibold', 10),
                padx=12,
                pady=5,
            )
            self.video_mode_badge.place(relx=0.012, rely=0.018, anchor='nw')
            self.overlay_var = tk.StringVar(value='Idle')
            self.overlay_bg = _blend_hex_color(self.palette['panel'], self.palette['surface'], 0.62)
            self.overlay = tk.Label(
                self.video_frame,
                textvariable=self.overlay_var,
                fg=self.palette['text'],
                bg=self.overlay_bg,
                font=('Segoe UI Semibold', 18),
                padx=24,
                pady=16,
                justify='center',
            )
            self.overlay.place(relx=0.5, rely=0.5, anchor='center')
            self.startup_progress = tk.Frame(self.video_frame, bg=self.palette['panel'], highlightthickness=1, highlightbackground=self.palette['border'])
            self.startup_progress_var = tk.StringVar(value='')
            self.startup_progress_percent_var = tk.StringVar(value='')
            startup_progress_row = tk.Frame(self.startup_progress, bg=self.palette['panel'])
            startup_progress_row.pack(fill='x', padx=10, pady=5)
            tk.Label(
                startup_progress_row,
                textvariable=self.startup_progress_percent_var,
                fg=self.palette['text'],
                bg=self.palette['panel'],
                font=('Segoe UI Semibold', 9),
                anchor='e',
                padx=8,
                width=5,
            ).pack(side='right')
            tk.Label(
                startup_progress_row,
                textvariable=self.startup_progress_var,
                fg=self.palette['text'],
                bg=self.palette['panel'],
                font=('Segoe UI', 9),
                anchor='w',
            ).pack(side='left', fill='x', expand=True)
            self.startup_progress_track = tk.Frame(self.startup_progress, bg=self.palette['border'], height=4)
            self.startup_progress_track.pack(fill='x', padx=10, pady=(0, 8))
            self.startup_progress_track.pack_propagate(False)
            self.startup_progress_fill = tk.Frame(self.startup_progress_track, bg=self.palette['accent'], height=4)
            self.startup_progress_fill.place(relx=0, rely=0, relheight=1, relwidth=0)
            self.startup_progress_pulse = tk.Frame(self.startup_progress_fill, bg=self.palette['text'], height=4)
            self.startup_progress_pulse.place_forget()
            self.ptz_panel = tk.Frame(
                self.video_frame,
                bg=self.overlay_bg,
                highlightthickness=1,
                highlightbackground=self.palette['border'],
            )
            self._build_ptz_panel()

            toolbar = tk.Frame(live_page, bg=self.palette['panel'], highlightthickness=1, highlightbackground=self.palette['border'])
            self.toolbar = toolbar
            toolbar.pack(fill='x')
            buttons = [
                ('Play', self._on_play, 'normal'),
                ('Stop', self._on_stop, 'normal'),
                ('Reconnect', self._on_reconnect, 'normal'),
                ('SD', self._set_sd, 'normal'),
                ('HD', self._set_hd, 'normal'),
                ('Layout', self._toggle_video_layout, 'normal'),
                ('Fullscreen', self._toggle_fullscreen, 'normal'),
                ('Screenshot', self._save_screenshot, 'normal'),
                ('Voice', None, 'disabled'),
                ('Intercom', None, 'disabled'),
                ('PTZ', self._toggle_ptz_panel, 'normal'),
            ]
            for text, cmd, state in buttons:
                btn = tk.Button(
                    toolbar,
                    text=text,
                    command=cmd,
                    state=state,
                    relief='flat',
                    bd=0,
                    padx=14,
                    pady=10,
                    bg=self.palette['panel'],
                    fg=self.palette['text'] if state == 'normal' else self.palette['muted'],
                    activebackground=self.palette['border'],
                    activeforeground=self.palette['text'],
                    disabledforeground=self.palette['muted'],
                    font=('Segoe UI', 10, 'bold' if text in {'Play', 'Reconnect'} else 'normal'),
                )
                btn.pack(side='left', padx=6, pady=10)
                self._button_widgets[text] = btn

            self._section_pages['recordings'] = self._build_recordings_page(self.section_host)
            self._section_pages['messages'] = self._build_messages_page(self.section_host)
            self._show_section('live')

        def _change_connection(self) -> None:
            if self._connection_busy():
                return
            if self._wifi_dialog is not None and self._wifi_dialog.winfo_exists():
                self._wifi_dialog.lift()
                self._set_state('Idle', 'Close Camera Wi-Fi before changing connection')
                return
            from .connection import prompt_for_connection
            if prompt_for_connection(self.config_data, parent=self):
                self._restart_app = True
                self._on_close()

        def _connection_busy(self) -> bool:
            return self._worker_alive() or any(
                worker is not None and worker.is_alive()
                for worker in (self._recordings_worker, self._messages_worker))

        def _open_wifi_settings(self) -> None:
            if self._wifi_dialog is not None and self._wifi_dialog.winfo_exists():
                self._wifi_dialog.lift()
                self._wifi_dialog.focus_set()
                return
            self._wifi_dialog = CameraWifiDialog(
                self, self.config_data, self.palette, before_save=self._on_stop,
            )

        def _build_ptz_panel(self) -> None:
            button_style = {
                'relief': 'flat',
                'bd': 0,
                'width': 6,
                'padx': 8,
                'pady': 8,
                'bg': self.palette['panel'],
                'fg': self.palette['text'],
                'activebackground': self.palette['accent'],
                'activeforeground': 'white',
                'font': ('Segoe UI Semibold', 9),
                'cursor': 'hand2',
            }
            tk.Label(
                self.ptz_panel,
                text='PTZ',
                fg=self.palette['muted'],
                bg=self.overlay_bg,
                font=('Segoe UI Semibold', 9),
                padx=8,
                pady=4,
            ).grid(row=0, column=0, columnspan=3, sticky='ew')
            tk.Button(self.ptz_panel, text='Up', command=lambda: self._send_ptz_pulse('up'), **button_style).grid(row=1, column=1, padx=4, pady=4)
            tk.Button(self.ptz_panel, text='Left', command=lambda: self._send_ptz_pulse('left'), **button_style).grid(row=2, column=0, padx=4, pady=4)
            tk.Button(self.ptz_panel, text='Right', command=lambda: self._send_ptz_pulse('right'), **button_style).grid(row=2, column=2, padx=4, pady=4)
            tk.Button(self.ptz_panel, text='Down', command=lambda: self._send_ptz_pulse('down'), **button_style).grid(row=3, column=1, padx=4, pady=(4, 8))

        def _ptz_controls_enabled(self) -> bool:
            return self._worker_alive() and self._current_recording is None and not self._closing

        def _toggle_ptz_panel(self) -> None:
            if not self._ptz_controls_enabled():
                self._hide_ptz_panel()
                return
            if self._ptz_panel_visible:
                self._hide_ptz_panel()
                return
            self.ptz_panel.place(relx=0.985, rely=0.5, anchor='e')
            self.ptz_panel.lift()
            self._ptz_panel_visible = True

        def _hide_ptz_panel(self) -> None:
            self._ptz_panel_visible = False
            if hasattr(self, 'ptz_panel'):
                self.ptz_panel.place_forget()

        def _send_ptz_pulse(self, direction: str, *, hold: float = 0.65) -> None:
            if not self._ptz_controls_enabled():
                self._hide_ptz_panel()
                return
            try:
                code = self._ptz_queue.enqueue_pulse(direction, hold=hold, label=direction)
            except Exception as exc:  # noqa: BLE001
                self._set_state('Error', f'PTZ command failed: {exc}')
                return
            self.detail_var.set(f'PTZ {direction} queued code={code}')
            self.overlay.place_forget()

        def _show_section(self, section: str) -> None:
            section = section if section in self._section_pages else 'live'
            self._active_section = section
            for page in self._section_pages.values():
                page.pack_forget()
            self._section_pages[section].pack(fill='both', expand=True)
            for key, button in self._section_buttons.items():
                selected = key == section
                button.configure(
                    bg=self.palette['accent'] if selected else self.palette['panel'],
                    fg='white' if selected else self.palette['muted'],
                )
            if section == 'recordings' and not self._recordings_loaded:
                self._refresh_recordings()
            if section == 'messages' and not self._messages_loaded:
                self._refresh_messages()

        def _build_recordings_page(self, parent):
            page = tk.Frame(parent, bg=self.palette['bg'])
            shell = tk.Frame(page, bg=self.palette['panel'], highlightthickness=1, highlightbackground=self.palette['border'])
            shell.pack(fill='both', expand=True)

            top = tk.Frame(shell, bg=self.palette['panel'])
            top.pack(fill='x', padx=18, pady=(18, 8))
            tk.Label(top, text='Today', fg=self.palette['text'], bg=self.palette['panel'], font=('Segoe UI Semibold', 16)).pack(side='left')
            self.recordings_count_var = tk.StringVar(value='Recordings: 0')
            refresh = tk.Button(
                top,
                text='Refresh',
                command=self._refresh_recordings,
                relief='flat',
                bd=0,
                padx=12,
                pady=6,
                bg=self.palette['accent'],
                fg='white',
                activebackground=self.palette['border'],
                activeforeground=self.palette['text'],
                font=('Segoe UI Semibold', 10),
            )
            refresh.pack(side='right')
            self.recordings_refresh_button = refresh
            tk.Label(top, textvariable=self.recordings_count_var, fg=self.palette['muted'], bg=self.palette['panel'], font=('Segoe UI', 10)).pack(side='right', padx=14)

            self.recordings_status_var = tk.StringVar(value='')

            body_shell = tk.Frame(shell, bg=self.palette['surface'])
            body_shell.pack(fill='both', expand=True, padx=18, pady=(0, 18))
            self.recordings_canvas = tk.Canvas(body_shell, bg=self.palette['surface'], highlightthickness=0, bd=0)
            self.recordings_scrollbar = tk.Scrollbar(body_shell, orient='vertical', command=self.recordings_canvas.yview)
            self.recordings_canvas.configure(yscrollcommand=self.recordings_scrollbar.set)
            self.recordings_scrollbar.pack(side='right', fill='y')
            self.recordings_canvas.pack(side='left', fill='both', expand=True)
            self.recordings_body = tk.Frame(self.recordings_canvas, bg=self.palette['surface'])
            self._recordings_body_window = self.recordings_canvas.create_window((0, 0), window=self.recordings_body, anchor='nw')
            self.recordings_body.bind(
                '<Configure>',
                lambda _event: self.recordings_canvas.configure(scrollregion=self.recordings_canvas.bbox('all')),
            )
            self.recordings_canvas.bind(
                '<Configure>',
                lambda event: self.recordings_canvas.itemconfigure(self._recordings_body_window, width=event.width),
            )
            self.recordings_canvas.bind('<Enter>', lambda _event: self.bind_all('<MouseWheel>', self._on_recordings_mousewheel))
            self.recordings_canvas.bind('<Leave>', lambda _event: self.unbind_all('<MouseWheel>'))
            self._render_recordings([])
            return page

        def _recordings_worker_alive(self) -> bool:
            return self._recordings_worker is not None and self._recordings_worker.is_alive()

        def _on_recordings_mousewheel(self, event) -> None:
            delta = int(-1 * (event.delta / 120)) if getattr(event, 'delta', 0) else 0
            if delta == 0:
                delta = -1 if getattr(event, 'delta', 0) > 0 else 1
            self.recordings_canvas.yview_scroll(delta, 'units')

        def _refresh_recordings(self) -> None:
            if self._closing or self._recordings_worker_alive():
                return
            self._recordings_loaded = True
            self.recordings_count_var.set('Recordings: ...')
            self.recordings_refresh_button.configure(state='disabled')
            self._render_recordings([], empty_text='Loading recordings...')
            self._recordings_generation += 1
            generation = self._recordings_generation

            def _worker() -> None:
                try:
                    recordings, meta = fetch_device_recordings(self.config_data, timeout=20)
                    self._ui_queue.put(('recordings', recordings, {'meta': meta, 'generation': generation}))
                except Exception as exc:  # noqa: BLE001
                    self._ui_queue.put(('recordings_error', str(exc), {'generation': generation}))

            self._recordings_worker = threading.Thread(target=_worker, daemon=True, name='xmplayer-recordings-worker')
            self._recordings_worker.start()

        def _format_recording_duration(self, seconds: int) -> str:
            value = max(int(seconds or 0), 0)
            minutes, sec = divmod(value, 60)
            hours, minutes = divmod(minutes, 60)
            if hours:
                return f'{hours:d}:{minutes:02d}:{sec:02d}'
            return f'{minutes:d}:{sec:02d}'

        def _render_recordings(
            self,
            recordings: list[RecordingItem],
            *,
            empty_text: str = 'No recordings yet',
        ) -> None:
            scroll_position = 0.0
            try:
                scroll_position = float(self.recordings_canvas.yview()[0])
            except Exception:
                scroll_position = 0.0
            for child in self.recordings_body.winfo_children():
                child.destroy()
            if not recordings:
                empty = tk.Frame(self.recordings_body, bg=self.palette['surface'])
                empty.pack(fill='both', expand=True)
                tk.Label(
                    empty,
                    text=empty_text,
                    fg=self.palette['muted'],
                    bg=self.palette['surface'],
                    font=('Segoe UI Semibold', 14),
                ).pack(anchor='center', expand=True)
                self.recordings_canvas.configure(scrollregion=self.recordings_canvas.bbox('all'))
                return
            for item in recordings:
                card = tk.Frame(self.recordings_body, bg=self.palette['panel'], highlightthickness=1, highlightbackground=self.palette['border'])
                card.pack(fill='x', padx=18, pady=(18, 0))
                row = tk.Frame(card, bg=self.palette['panel'])
                row.pack(fill='x', padx=14, pady=12)
                icon = tk.Label(row, text='>', fg='white', bg=self.palette['badge_sd'], font=('Segoe UI Semibold', 11), width=2)
                icon.pack(side='left', padx=(0, 12))
                text_box = tk.Frame(row, bg=self.palette['panel'])
                text_box.pack(side='left', fill='x', expand=True)
                tk.Label(text_box, text=item.title, fg=self.palette['text'], bg=self.palette['panel'], font=('Segoe UI Semibold', 12)).pack(anchor='w')
                period = f'{item.start_time}  ->  {item.end_time}' if item.end_time else item.start_time
                tk.Label(text_box, text=period, fg=self.palette['muted'], bg=self.palette['panel'], font=('Segoe UI', 10)).pack(anchor='w', pady=(2, 0))
                detail_parts = []
                if item.duration_seconds:
                    detail_parts.append(f'duration {self._format_recording_duration(item.duration_seconds)}')
                if item.file_length:
                    detail_parts.append(f'{item.file_length} KB')
                if item.file_name:
                    detail_parts.append(item.file_name)
                if detail_parts:
                    tk.Label(text_box, text=' · '.join(detail_parts), fg=self.palette['muted'], bg=self.palette['panel'], font=('Segoe UI', 9)).pack(anchor='w', pady=(2, 0))
                tk.Button(
                    row,
                    text='Play',
                    command=lambda selected=item: self._on_recording_play(selected),
                    state='normal',
                    relief='flat',
                    bd=0,
                    padx=12,
                    pady=6,
                    bg=self.palette['accent'],
                    fg='white',
                    disabledforeground=self.palette['muted'],
                    font=('Segoe UI Semibold', 10),
                ).pack(side='right', padx=(12, 0))
            self.recordings_canvas.configure(scrollregion=self.recordings_canvas.bbox('all'))
            try:
                self.recordings_canvas.yview_moveto(scroll_position)
            except Exception:
                pass

        def _handle_recordings_result(self, recordings: list[RecordingItem], meta: dict[str, Any]) -> None:
            total_count = meta.get('total_count')
            if total_count not in (None, ''):
                self.recordings_count_var.set(f'Recordings: {total_count}')
            else:
                self.recordings_count_var.set(f'Recordings: {len(recordings)}')
            ret = meta.get('response_ret')
            if ret not in (None, ''):
                self.recordings_status_var.set(f'OPFileQuery Ret={ret}')
            else:
                self.recordings_status_var.set('Camera recordings loaded')
            self.recordings_refresh_button.configure(state='normal')
            self._render_recordings(recordings)

        def _handle_recordings_error(self, message: str) -> None:
            self.recordings_count_var.set('Recordings: 0')
            self.recordings_status_var.set(f'Failed to load recordings: {message}')
            self.recordings_refresh_button.configure(state='normal')
            self._render_recordings([], empty_text=f'Failed to load recordings: {message}')

        def _build_messages_page(self, parent):
            page = tk.Frame(parent, bg=self.palette['bg'])
            shell = tk.Frame(page, bg=self.palette['panel'], highlightthickness=1, highlightbackground=self.palette['border'])
            shell.pack(fill='both', expand=True)

            top = tk.Frame(shell, bg=self.palette['panel'])
            top.pack(fill='x', padx=18, pady=(18, 8))
            tk.Label(top, text='Today', fg=self.palette['text'], bg=self.palette['panel'], font=('Segoe UI Semibold', 16)).pack(side='left')
            self.messages_count_var = tk.StringVar(value='Messages: 0')
            refresh = tk.Button(
                top,
                text='Refresh',
                command=self._refresh_messages,
                relief='flat',
                bd=0,
                padx=12,
                pady=6,
                bg=self.palette['accent'],
                fg='white',
                activebackground=self.palette['border'],
                activeforeground=self.palette['text'],
                font=('Segoe UI Semibold', 10),
            )
            refresh.pack(side='right')
            self.messages_refresh_button = refresh
            tk.Label(top, textvariable=self.messages_count_var, fg=self.palette['muted'], bg=self.palette['panel'], font=('Segoe UI', 10)).pack(side='right', padx=14)

            self.messages_status_var = tk.StringVar(value='')

            body_shell = tk.Frame(shell, bg=self.palette['surface'])
            body_shell.pack(fill='both', expand=True, padx=18, pady=(0, 18))
            self.messages_canvas = tk.Canvas(body_shell, bg=self.palette['surface'], highlightthickness=0, bd=0)
            self.messages_scrollbar = tk.Scrollbar(body_shell, orient='vertical', command=self.messages_canvas.yview)
            self.messages_canvas.configure(yscrollcommand=self.messages_scrollbar.set)
            self.messages_scrollbar.pack(side='right', fill='y')
            self.messages_canvas.pack(side='left', fill='both', expand=True)
            self.messages_body = tk.Frame(self.messages_canvas, bg=self.palette['surface'])
            self._messages_body_window = self.messages_canvas.create_window((0, 0), window=self.messages_body, anchor='nw')
            self.messages_body.bind(
                '<Configure>',
                lambda _event: self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox('all')),
            )
            self.messages_canvas.bind(
                '<Configure>',
                lambda event: self.messages_canvas.itemconfigure(self._messages_body_window, width=event.width),
            )
            self.messages_canvas.bind('<Enter>', lambda _event: self.bind_all('<MouseWheel>', self._on_messages_mousewheel))
            self.messages_canvas.bind('<Leave>', lambda _event: self.unbind_all('<MouseWheel>'))
            self._render_messages([])
            return page

        def _messages_worker_alive(self) -> bool:
            return self._messages_worker is not None and self._messages_worker.is_alive()

        def _on_messages_mousewheel(self, event) -> None:
            delta = int(-1 * (event.delta / 120)) if getattr(event, 'delta', 0) else 0
            if delta == 0:
                delta = -1 if getattr(event, 'delta', 0) > 0 else 1
            self.messages_canvas.yview_scroll(delta, 'units')

        def _refresh_messages(self) -> None:
            if self._closing or self._messages_worker_alive():
                return
            self._messages_loaded = True
            self.messages_count_var.set('Messages: ...')
            self.messages_refresh_button.configure(state='disabled')
            self._render_messages([], empty_text='Loading messages...')
            self._messages_generation += 1
            generation = self._messages_generation

            def _worker() -> None:
                try:
                    messages, meta = fetch_monitor_messages(self.config_data, limit=0, timeout=12)
                    self._ui_queue.put(('messages', messages, {'meta': meta, 'thumbs': {}, 'generation': generation}))
                    thumbs_batch: dict[int, list[Any]] = {}
                    for index, item in enumerate(messages):
                        if self._closing or generation != self._messages_generation:
                            return
                        item_thumbs = self._load_message_thumbnails(item)
                        if item_thumbs:
                            thumbs_batch[index] = item_thumbs
                        if len(thumbs_batch) >= 6:
                            self._ui_queue.put(('messages_thumbs', None, {'thumbs': thumbs_batch, 'generation': generation}))
                            thumbs_batch = {}
                    if thumbs_batch:
                        self._ui_queue.put(('messages_thumbs', None, {'thumbs': thumbs_batch, 'generation': generation}))
                except Exception as exc:  # noqa: BLE001
                    self._ui_queue.put(('messages_error', str(exc), {'generation': generation}))

            self._messages_worker = threading.Thread(target=_worker, daemon=True, name='xmplayer-messages-worker')
            self._messages_worker.start()

        def _load_message_thumbnails(self, item: MonitorMessage) -> list[Any]:
            urls = list(item.image_urls or ([item.image_url] if item.image_url else []))
            row_thumbs: list[Any] = []
            for url in urls[:4]:
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'xmplayer'})
                    context = ssl._create_unverified_context() if str(url).lower().startswith('https://') else None
                    with urllib.request.urlopen(req, timeout=4, context=context) as response:
                        data = response.read(1_500_000)
                    image = self.Image.open(BytesIO(data)).convert('RGB')
                    if self.config_data.display_mode == 'stacked_split' or image.height > image.width:
                        image = _stacked_split_view(image, self.Image)
                    full_image = image.copy()
                    thumb_image = image.copy()
                    thumb_image.thumbnail((230, 124))
                    row_thumbs.append({'thumb': thumb_image.copy(), 'full': full_image})
                except Exception:
                    continue
            return row_thumbs

        def _render_messages(
            self,
            messages: list[MonitorMessage],
            thumbs: dict[int, list[Any]] | None = None,
            *,
            empty_text: str = 'No messages yet',
        ) -> None:
            thumbs = thumbs or {}
            scroll_position = 0.0
            try:
                scroll_position = float(self.messages_canvas.yview()[0])
            except Exception:
                scroll_position = 0.0
            self._message_thumb_images.clear()
            self._message_thumb_refs.clear()
            self._message_thumb_hosts.clear()
            self._message_full_images.clear()
            for child in self.messages_body.winfo_children():
                child.destroy()
            if not messages:
                empty = tk.Frame(self.messages_body, bg=self.palette['surface'])
                empty.pack(fill='both', expand=True)
                tk.Label(
                    empty,
                    text=empty_text,
                    fg=self.palette['muted'],
                    bg=self.palette['surface'],
                    font=('Segoe UI Semibold', 14),
                ).pack(anchor='center', expand=True)
                self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox('all'))
                return
            for index, item in enumerate(messages):
                card = tk.Frame(self.messages_body, bg=self.palette['panel'], highlightthickness=1, highlightbackground=self.palette['border'])
                card.pack(fill='x', padx=18, pady=(18, 0))
                row = tk.Frame(card, bg=self.palette['panel'])
                row.pack(fill='x', padx=14, pady=10)
                icon = tk.Label(row, text='!', fg='white', bg=self.palette['accent'], font=('Segoe UI Semibold', 13), width=2)
                icon.pack(side='left', padx=(0, 12))
                text_box = tk.Frame(row, bg=self.palette['panel'])
                text_box.pack(side='left', fill='x', expand=True)
                tk.Label(text_box, text=item.title, fg=self.palette['text'], bg=self.palette['panel'], font=('Segoe UI Semibold', 12)).pack(anchor='w')
                time_text = item.timestamp or 'Time unavailable'
                tk.Label(text_box, text=time_text, fg=self.palette['muted'], bg=self.palette['panel'], font=('Segoe UI', 10)).pack(anchor='w', pady=(2, 0))
                if item.detail:
                    tk.Label(text_box, text=item.detail[:120], fg=self.palette['muted'], bg=self.palette['panel'], font=('Segoe UI', 9)).pack(anchor='w', pady=(2, 0))
                thumb_host = tk.Frame(row, bg=self.palette['panel'], bd=0, highlightthickness=0)
                thumb_host.pack(side='right')
                self._message_thumb_hosts[index] = thumb_host
            if thumbs:
                self._apply_message_thumbnails(thumbs)
            self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox('all'))
            try:
                self.messages_canvas.yview_moveto(scroll_position)
            except Exception:
                pass

        def _apply_message_thumbnails(self, thumbs: dict[int, list[Any]]) -> None:
            for index, item_thumbs in thumbs.items():
                host = self._message_thumb_hosts.get(index)
                if host is None:
                    continue
                for child in host.winfo_children():
                    child.destroy()
                for key in [key for key in self._message_full_images if key[0] == index]:
                    self._message_full_images.pop(key, None)
                refs: list[Any] = []
                for thumb_index, item in enumerate(item_thumbs or []):
                    if isinstance(item, dict):
                        thumb = item.get('thumb')
                        full_image = item.get('full') or thumb
                    else:
                        thumb = item
                        full_image = item
                    if thumb is None:
                        continue
                    self._message_full_images[(index, thumb_index)] = full_image
                    photo = self.ImageTk.PhotoImage(thumb)
                    refs.append(photo)
                    label = tk.Label(
                        host,
                        image=photo,
                        bg=self.palette['panel'],
                        bd=0,
                        highlightthickness=0,
                        padx=0,
                        pady=0,
                        cursor='hand2',
                    )
                    label.pack(side='left', padx=(6 if thumb_index else 0, 0), pady=0)
                    label.bind('<Button-1>', lambda _event, row=index, pos=thumb_index: self._show_message_image(row, pos))
                    label.bind('<ButtonRelease-1>', lambda _event, row=index, pos=thumb_index: self._show_message_image(row, pos))
                if refs:
                    self._message_thumb_refs[index] = refs
                else:
                    self._message_thumb_refs.pop(index, None)
            self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox('all'))

        def _message_image_keys(self) -> list[tuple[int, int]]:
            return sorted(self._message_full_images)

        def _navigate_message_image(self, step: int) -> str:
            keys = self._message_image_keys()
            if not keys:
                self._close_message_image()
                return 'break'
            current_key = self._message_viewer_key
            if current_key not in keys:
                target_key = keys[0]
            else:
                current_index = keys.index(current_key)
                target_key = keys[(current_index + int(step)) % len(keys)]
            self._show_message_image(*target_key, zoom=self._message_viewer_zoom)
            return 'break'

        def _message_viewer_resample_filter(self):
            resampling = getattr(self.Image, 'Resampling', None)
            if resampling is not None:
                return resampling.LANCZOS
            return getattr(self.Image, 'LANCZOS', getattr(self.Image, 'BICUBIC', 1))

        def _render_message_viewer_image(self) -> None:
            image = self._message_viewer_source
            label = self._message_viewer_label
            if image is None or label is None:
                return
            self.update_idletasks()
            max_width = max(int(self.winfo_width() * 0.86), 1)
            max_height = max(int(self.winfo_height() * 0.82), 1)
            fit_scale = min(max_width / image.width, max_height / image.height, 1.0)
            fit_width = max(int(image.width * fit_scale), 1)
            fit_height = max(int(image.height * fit_scale), 1)
            width = max(int(fit_width * self._message_viewer_zoom), 1)
            height = max(int(fit_height * self._message_viewer_zoom), 1)
            if (width, height) == (image.width, image.height):
                display_image = image
            else:
                display_image = image.resize((width, height), self._message_viewer_resample_filter())
            self._message_viewer_photo = self.ImageTk.PhotoImage(display_image)
            label.configure(image=self._message_viewer_photo)
            if self._message_viewer_zoom_var is not None:
                self._message_viewer_zoom_var.set(f'{self._message_viewer_zoom:.1f}x')

        def _set_message_viewer_zoom(self, zoom: float) -> str:
            self._message_viewer_zoom = min(max(float(zoom), 0.5), 4.0)
            self._render_message_viewer_image()
            return 'break'

        def _change_message_viewer_zoom(self, delta: float) -> str:
            return self._set_message_viewer_zoom(self._message_viewer_zoom + delta)

        def _message_viewer_mousewheel(self, event) -> str:
            delta = getattr(event, 'delta', 0)
            step = 0.2 if delta >= 0 else -0.2
            return self._change_message_viewer_zoom(step)

        def _show_message_image(self, message_index: int, image_index: int, zoom: float | None = None) -> None:
            image = self._message_full_images.get((message_index, image_index))
            if image is None:
                return
            self._close_message_image()
            viewer = tk.Frame(self, bg=self.palette['surface'], bd=0, highlightthickness=0)
            self._message_viewer = viewer
            self._message_viewer_key = (message_index, image_index)
            self._message_viewer_source = image
            self._message_viewer_zoom = 1.0 if zoom is None else min(max(float(zoom), 0.5), 4.0)
            self._message_viewer_zoom_var = tk.StringVar(value=f'{self._message_viewer_zoom:.1f}x')
            viewer.place(relx=0, rely=0, relwidth=1, relheight=1)
            viewer.lift()
            viewer.bind('<Button-1>', lambda _event: self._close_message_image())

            label = tk.Label(
                viewer,
                bg=self.palette['surface'],
                bd=0,
                highlightthickness=0,
                padx=0,
                pady=0,
                cursor='hand2',
            )
            label.place(relx=0.5, rely=0.5, anchor='center')
            label.bind('<Button-1>', lambda _event: self._close_message_image())
            label.bind('<MouseWheel>', self._message_viewer_mousewheel)
            self._message_viewer_label = label
            self._render_message_viewer_image()

            keys = self._message_image_keys()
            button_style = {
                'relief': 'flat',
                'bd': 0,
                'width': 7,
                'padx': 10,
                'pady': 8,
                'bg': self.palette['panel'],
                'fg': self.palette['text'],
                'activebackground': self.palette['accent'],
                'activeforeground': 'white',
                'font': ('Segoe UI Semibold', 10),
                'cursor': 'hand2',
            }
            if len(keys) > 1:
                nav = tk.Frame(viewer, bg=self.palette['surface'], bd=0, highlightthickness=0)
                nav.place(relx=0.975, rely=0.5, anchor='e')
                tk.Button(nav, text='Up', command=lambda: self._navigate_message_image(-1), **button_style).pack(fill='x')
                tk.Label(
                    nav,
                    text=f'{keys.index((message_index, image_index)) + 1}/{len(keys)}',
                    fg=self.palette['muted'],
                    bg=self.palette['surface'],
                    font=('Segoe UI', 9),
                    pady=8,
                ).pack(fill='x')
                tk.Button(nav, text='Down', command=lambda: self._navigate_message_image(1), **button_style).pack(fill='x')

            zoom_controls = tk.Frame(viewer, bg=self.palette['surface'], bd=0, highlightthickness=0)
            zoom_controls.place(relx=0.975, rely=0.04, anchor='ne')
            tk.Button(zoom_controls, text='+', command=lambda: self._change_message_viewer_zoom(0.2), **button_style).pack(side='left')
            tk.Label(
                zoom_controls,
                textvariable=self._message_viewer_zoom_var,
                fg=self.palette['muted'],
                bg=self.palette['surface'],
                font=('Segoe UI Semibold', 10),
                width=5,
                padx=8,
            ).pack(side='left')
            tk.Button(zoom_controls, text='-', command=lambda: self._change_message_viewer_zoom(-0.2), **button_style).pack(side='left')
            tk.Button(zoom_controls, text='Fit', command=lambda: self._set_message_viewer_zoom(1.0), **button_style).pack(side='left', padx=(8, 0))

            self.bind('<Up>', lambda _event: self._navigate_message_image(-1))
            self.bind('<Down>', lambda _event: self._navigate_message_image(1))
            self.bind('<plus>', lambda _event: self._change_message_viewer_zoom(0.2))
            self.bind('<KP_Add>', lambda _event: self._change_message_viewer_zoom(0.2))
            self.bind('<equal>', lambda _event: self._change_message_viewer_zoom(0.2))
            self.bind('<minus>', lambda _event: self._change_message_viewer_zoom(-0.2))
            self.bind('<KP_Subtract>', lambda _event: self._change_message_viewer_zoom(-0.2))
            self.bind('<Key-0>', lambda _event: self._set_message_viewer_zoom(1.0))
            viewer.bind('<MouseWheel>', self._message_viewer_mousewheel)
            viewer.focus_set()

        def _close_message_image(self) -> None:
            viewer = self._message_viewer
            self._message_viewer = None
            self._message_viewer_key = None
            self._message_viewer_photo = None
            self._message_viewer_source = None
            self._message_viewer_label = None
            self._message_viewer_zoom = 1.0
            self._message_viewer_zoom_var = None
            try:
                self.unbind('<Up>')
                self.unbind('<Down>')
                self.unbind('<plus>')
                self.unbind('<KP_Add>')
                self.unbind('<equal>')
                self.unbind('<minus>')
                self.unbind('<KP_Subtract>')
                self.unbind('<Key-0>')
            except Exception:
                pass
            if viewer is not None:
                try:
                    viewer.destroy()
                except Exception:
                    pass

        def _handle_messages_result(self, messages: list[MonitorMessage], meta: dict[str, Any], thumbs: dict[int, Any] | None = None) -> None:
            warning = str(meta.get('warning') or '')
            total_count = meta.get('total_count')
            if total_count not in (None, ''):
                self.messages_count_var.set(f'Messages: {total_count}')
            else:
                self.messages_count_var.set(f'Messages: {len(messages)}')
            if warning and not messages:
                self.messages_status_var.set(warning)
            elif warning:
                self.messages_status_var.set(warning)
            else:
                self.messages_status_var.set('Camera messages loaded')
            self.messages_refresh_button.configure(state='normal')
            self._render_messages(messages, thumbs)

        def _handle_messages_error(self, message: str) -> None:
            self.messages_count_var.set('Messages: 0')
            self.messages_status_var.set(f'Failed to load messages: {message}')
            self.messages_refresh_button.configure(state='normal')
            self._render_messages([], empty_text=f'Failed to load messages: {message}')

        def _recording_summary_text(self, recording: RecordingItem | None = None) -> str:
            item = recording or self._current_recording
            if item is None:
                return 'Camera live stream'
            period = item.start_time
            if item.end_time:
                period = f'{item.start_time}  ->  {item.end_time}'
            parts = [period]
            if item.duration_seconds:
                parts.append(f'duration {self._format_recording_duration(item.duration_seconds)}')
            if item.title:
                parts.append(item.title)
            return '   |   '.join(parts)

        def _update_mode_chrome(self) -> None:
            if not hasattr(self, 'mode_var'):
                return
            playback = self._current_recording is not None
            accent = self.palette['warn'] if playback else self.palette['accent']
            mode_text = 'RECORDING' if playback else 'LIVE'
            detail_text = self._recording_summary_text() if playback else 'Camera live stream'
            self.mode_var.set(mode_text)
            self.mode_detail_var.set(detail_text)
            self.mode_badge.configure(bg=accent)
            self.mode_detail_label.configure(fg=self.palette['text'] if playback else self.palette['muted'])
            self.video_mode_var.set('PLAYBACK' if playback else 'LIVE')
            self.video_mode_badge.configure(bg=accent)
            self.video_frame.configure(highlightbackground=accent if playback else self.palette['border'])
            if playback and not self._fullscreen:
                self.playback_banner_var.set(f'Recording playback: {detail_text}')
                self.playback_banner.configure(bg='#21190c', highlightbackground=accent)
                self.playback_banner_label.configure(bg='#21190c')
                if not self._playback_banner_packed:
                    self.playback_banner.pack(fill='x', pady=(0, 10), before=self.video_frame)
                    self._playback_banner_packed = True
            elif self._playback_banner_packed:
                self.playback_banner.pack_forget()
                self._playback_banner_packed = False
            self.video_mode_badge.lift()
            if playback:
                self.status_label.pack_forget()
                self.detail_label.pack_forget()
            else:
                if not self.status_label.winfo_manager():
                    self.status_label.pack(anchor='w', pady=(6, 0))
                if not self.detail_label.winfo_manager():
                    self.detail_label.pack(anchor='w')

        def _parse_startup_progress(self, detail: str) -> tuple[float | None, str]:
            text = str(detail or '')
            if not text.startswith('progress|'):
                return None, text
            parts = text.split('|', 3)
            if len(parts) != 4:
                return None, text
            try:
                step = max(0, int(parts[1]))
                total = max(1, int(parts[2]))
            except ValueError:
                return None, parts[-1].strip() or text
            label = parts[3].strip() or 'Starting stream'
            return min(max(step / total, 0.0), 0.98), f'{step}/{total} {label}'

        def _startup_progress_target(self, state: str, detail: str) -> float:
            parsed_progress, _label = self._parse_startup_progress(detail)
            if parsed_progress is not None:
                return parsed_progress
            detail_lower = detail.lower()
            if state == 'Retrying':
                return 0.18
            if state == 'Connecting':
                if 'preparing' in detail_lower:
                    return 0.12
                if 'cached' in detail_lower:
                    return 0.20
                if 'refreshing' in detail_lower:
                    return 0.26
                if 'attempt' in detail_lower:
                    return 0.38
                return 0.30
            if state == 'Buffering':
                if 'receiving' in detail_lower:
                    return 0.68
                if 'decoding' in detail_lower:
                    return 0.84
                if 'first frame' in detail_lower:
                    return 0.92
                return 0.74
            return 0.0

        def _cancel_startup_progress_animation(self) -> None:
            after_id = self._startup_progress_after_id
            self._startup_progress_after_id = None
            if after_id:
                try:
                    self.after_cancel(after_id)
                except Exception:
                    pass

        def _ensure_startup_progress_animation(self) -> None:
            if self._closing or self._startup_progress_after_id is not None:
                return
            self._startup_progress_after_id = self.after(30, self._animate_startup_progress)

        def _animate_startup_progress(self) -> None:
            self._startup_progress_after_id = None
            if self._closing or not hasattr(self, 'startup_progress'):
                return
            if not self.startup_progress.winfo_manager():
                return
            target = min(max(self._startup_progress_value, 0.0), 0.98)
            current = min(max(self._startup_progress_display_value, 0.0), 0.98)
            delta = target - current
            if abs(delta) < 0.003:
                current = target
            else:
                current += delta * 0.32
            self._startup_progress_display_value = min(max(current, 0.0), 0.98)
            accent = self.palette['warn'] if self._current_recording is not None else self.palette['accent']
            self.startup_progress_fill.configure(bg=accent)
            self.startup_progress_fill.place(relx=0, rely=0, relheight=1, relwidth=self._startup_progress_display_value)
            self._startup_progress_pulse = (self._startup_progress_pulse + 0.035) % 1.0
            if self._startup_progress_display_value < 0.04:
                self.startup_progress_pulse.place_forget()
            else:
                pulse_color = _blend_hex_color(self.palette['text'], accent, 0.38)
                self.startup_progress_pulse.configure(bg=pulse_color)
                pulse_width = min(0.42, max(0.18, 0.025 / self._startup_progress_display_value))
                pulse_x = self._startup_progress_pulse * (1.0 - pulse_width)
                self.startup_progress_pulse.place(relx=pulse_x, rely=0, relheight=1, relwidth=pulse_width)
                self.startup_progress_pulse.lift()
            self._ensure_startup_progress_animation()

        def _hide_startup_progress(self) -> None:
            self._startup_progress_value = 0.0
            self._startup_progress_display_value = 0.0
            self._startup_progress_pulse = 0.0
            self._cancel_startup_progress_animation()
            if hasattr(self, 'startup_progress'):
                self.startup_progress.place_forget()
                self.startup_progress_percent_var.set('')
                self.startup_progress_fill.place(relx=0, rely=0, relheight=1, relwidth=0)
                self.startup_progress_pulse.place_forget()

        def _update_startup_progress(self, state: str, detail: str) -> None:
            if state not in {'Connecting', 'Retrying', 'Buffering'}:
                self._hide_startup_progress()
                return
            target = self._startup_progress_target(state, detail)
            parsed_progress, parsed_label = self._parse_startup_progress(detail)
            if parsed_progress is not None:
                self._startup_progress_value = target
            elif state == 'Retrying':
                self._startup_progress_value = target
            else:
                self._startup_progress_value = max(self._startup_progress_value, target)
            progress = min(max(self._startup_progress_value, 0.0), 0.98)
            title = 'Loading recording' if self._current_recording is not None else 'Loading live stream'
            label = parsed_label or state
            self.startup_progress_var.set(f'{title}: {label}')
            self.startup_progress_percent_var.set(f'{int(progress * 100)}%')
            self.startup_progress_fill.configure(bg=self.palette['warn'] if self._current_recording is not None else self.palette['accent'])
            self.startup_progress.place(relx=0.5, rely=0.965, anchor='s', relwidth=0.92)
            self.startup_progress.lift()
            self.video_mode_badge.lift()
            self._ensure_startup_progress_animation()

        def _set_state(self, state: str, detail: str) -> None:
            raw_detail = detail
            _parsed_progress, display_detail = self._parse_startup_progress(raw_detail)
            self._status = state
            self._detail = display_detail
            self.status_var.set(state)
            self.detail_var.set(display_detail)
            color = self.palette['accent']
            if state in {'Retrying', 'No video'}:
                color = self.palette['warn']
            elif state == 'Error':
                color = self.palette['danger']
            elif state == 'Live' and self._current_recording is not None:
                color = self.palette['warn']
            self.status_label.configure(fg=color)
            if state == 'Live' or state in {'Connecting', 'Retrying', 'Buffering'}:
                self.overlay.place_forget()
            else:
                overlay_text = state if not display_detail else f'{state}\n{display_detail}'
                self.overlay_var.set(overlay_text)
                self.overlay.configure(bg=self.overlay_bg)
                self.overlay.place(relx=0.5, rely=0.5, anchor='center')
            self._update_mode_chrome()
            self._update_startup_progress(state, raw_detail)
            self._update_quality_badge()
            self._update_controls()

        def _handle_service_status(self, state: str, detail: str) -> None:
            if state == 'Buffering' and self._rendered_frame_count > 0:
                return
            if state == 'Live' and self._rendered_frame_count <= 0:
                buffering_detail = detail or 'Decoding video'
                self._set_state('Buffering', buffering_detail)
                return
            if state in {'Connecting', 'Retrying'}:
                if (
                    self._payload_activity_seen
                    or self._video_material_seen
                    or self._pending_frames
                    or self._rendered_frame_count > 0
                    or self._status in {'Buffering', 'Live'}
                ):
                    if self._rendered_frame_count > 0:
                        return
                    if str(detail or '').startswith('progress|'):
                        self._set_state('Buffering', detail)
                    else:
                        self._set_state('Buffering', 'Waiting for first frame')
                    return
            self._set_state(state, detail)

        def _update_quality_badge(self) -> None:
            if self._current_recording is not None:
                self.quality_var.set('REC HD')
                self.quality_badge.configure(bg=self.palette['warn'])
            else:
                self.quality_var.set(self._current_quality.upper())
                self.quality_badge.configure(bg=self.palette['badge_hd'] if self._current_quality == 'hd' else self.palette['badge_sd'])
            self._update_controls()

        def _worker_alive(self) -> bool:
            return self._worker is not None and self._worker.is_alive()

        def _cancel_restart_timer(self) -> None:
            if self._restart_after_id is None:
                return
            try:
                self.after_cancel(self._restart_after_id)
            except Exception:
                pass
            self._restart_after_id = None

        def _schedule_restart(self) -> None:
            self._cancel_restart_timer()
            if not self._closing:
                self._restart_after_id = self.after(150, self._restart_when_idle)

        def _queue_status(self, generation: int, state: str, detail: str) -> None:
            if self._closing or generation != self._session_generation:
                return
            self._ui_queue.put(('status', state, {'detail': detail, 'generation': generation}))

        def _update_controls(self) -> None:
            if not self._button_widgets:
                return
            worker_alive = self._worker_alive()
            restart_waiting = self._restart_pending or self._restart_after_id is not None
            if self._stop_pending and not worker_alive:
                self._stop_pending = False
            stopping = self._stop_pending and worker_alive

            def _state(enabled: bool) -> str:
                return 'normal' if enabled and not self._closing else 'disabled'

            play_enabled = not worker_alive and not restart_waiting and not stopping
            stop_enabled = (worker_alive or restart_waiting) and not stopping
            reconnect_enabled = not stopping and not restart_waiting
            quality_enabled = not stopping and not restart_waiting
            screenshot_enabled = self._last_pil_image is not None
            ptz_enabled = worker_alive and self._current_recording is None and not stopping and not restart_waiting

            mapping = {
                'Play': play_enabled,
                'Stop': stop_enabled,
                'Reconnect': reconnect_enabled,
                'SD': quality_enabled,
                'HD': quality_enabled,
                'Layout': True,
                'Fullscreen': True,
                'Screenshot': screenshot_enabled,
                'PTZ': ptz_enabled,
                'Connection': not self._connection_busy() and not restart_waiting,
            }
            for name, enabled in mapping.items():
                button = self._button_widgets.get(name)
                if button is not None:
                    button.configure(state=_state(enabled))
            play_button = self._button_widgets.get('Play')
            if play_button is not None:
                play_button.configure(text='Live' if self._current_recording is not None else 'Play')
            layout_button = self._button_widgets.get('Layout')
            if layout_button is not None:
                layout_button.configure(
                    text='Horizontal' if self._video_layout == 'horizontal' else 'Vertical',
                    bg=self.palette['accent'] if self._video_layout == 'horizontal' else self.palette['panel'],
                    fg='white' if self._video_layout == 'horizontal' else self.palette['text'],
                )
            for name, quality in (('SD', 'sd'), ('HD', 'hd')):
                button = self._button_widgets.get(name)
                if button is None:
                    continue
                selected = self._current_quality == quality
                button.configure(
                    bg=self.palette['badge_hd'] if selected and quality == 'hd' else self.palette['badge_sd'] if selected else self.palette['panel'],
                    fg='white' if selected else self.palette['text'],
                )
            if not ptz_enabled:
                self._hide_ptz_panel()

        def _on_play(self) -> None:
            if self._worker_alive() or self._restart_pending or self._restart_after_id is not None:
                return
            self._current_recording = None
            self._start_session(reconnect=False)

        def _on_recording_play(self, recording: RecordingItem) -> None:
            if self._closing:
                return
            self._current_recording = recording
            self._show_section('live')
            self._start_session(reconnect=self._worker_alive(), recording=recording)

        def _on_stop(self) -> None:
            self._cancel_restart_timer()
            self._restart_pending = False
            self._session_generation += 1
            self._current_recording = None
            self._stop_pending = self._worker_alive()
            self._stop_current_session()
            self._set_state('Idle', 'Playback stopped')
            self._update_controls()

        def _on_reconnect(self) -> None:
            self._start_session(reconnect=True, recording=self._current_recording)

        def _set_sd(self) -> None:
            if self._current_quality == 'sd':
                return
            self._current_quality = 'sd'
            self._update_quality_badge()
            if self._worker_alive():
                self._start_session(reconnect=True, recording=self._current_recording)

        def _set_hd(self) -> None:
            if self._current_quality == 'hd':
                return
            self._current_quality = 'hd'
            self._update_quality_badge()
            if self._worker_alive():
                self._start_session(reconnect=True, recording=self._current_recording)

        def _toggle_video_layout(self) -> None:
            self._video_layout = 'vertical' if self._video_layout == 'horizontal' else 'horizontal'
            if self._last_source_image is not None:
                self._show_display_image(self._prepare_display_image(self._last_source_image))
            self._update_controls()

        def _toggle_fullscreen(self) -> None:
            if self._closing:
                return
            if not self._fullscreen:
                self._windowed_state = self.state()
                self._windowed_geometry = self.geometry()
                self._show_section('live')
                self._fullscreen = True
                self.header.pack_forget()
                self.tabbar.pack_forget()
                self.section_host.pack_configure(padx=0, pady=0)
                self.toolbar.pack_forget()
                self.video_frame.pack_configure(pady=0)
                self.video_frame.configure(highlightthickness=0)
                self.video_mode_badge.place_forget()
                self._update_mode_chrome()
                self.attributes('-fullscreen', True)
                self.focus_set()
                self._fullscreen_after_id = self.after(100, self._sync_fullscreen_controls)
            else:
                self._fullscreen = False
                if self._fullscreen_after_id is not None:
                    self.after_cancel(self._fullscreen_after_id)
                    self._fullscreen_after_id = None
                self.toolbar.place_forget()
                self.video_frame.pack_configure(pady=(0, 10))
                self.video_frame.configure(highlightthickness=1)
                self.toolbar.pack(fill='x')
                self.section_host.pack_configure(padx=18, pady=(0, 18))
                self.header.pack(fill='x', padx=18, pady=(18, 10), before=self.section_host)
                self.tabbar.pack(fill='x', padx=18, pady=(0, 10), after=self.header)
                self.video_mode_badge.place(relx=0.012, rely=0.018, anchor='nw')
                self._update_mode_chrome()
                self.attributes('-fullscreen', False)
                self.state(self._windowed_state)
                if self._windowed_state == 'normal' and self._windowed_geometry:
                    self.geometry(self._windowed_geometry)
            self._schedule_video_redraw()

        def _on_escape(self, _event=None) -> str:
            if self._message_viewer is not None:
                self._close_message_image()
            elif self._fullscreen:
                self._toggle_fullscreen()
            return 'break'

        def _sync_fullscreen_controls(self) -> None:
            self._fullscreen_after_id = None
            if self._closing or not self._fullscreen:
                return
            pointer_x, pointer_y = self.winfo_pointerxy()
            left = self.video_frame.winfo_rootx()
            top = self.video_frame.winfo_rooty()
            width = self.video_frame.winfo_width()
            height = self.video_frame.winfo_height()
            reveal_height = max(self.toolbar.winfo_reqheight() + 16, 80)
            near_bottom = (
                left <= pointer_x < left + width
                and top + max(height - reveal_height, 0) <= pointer_y < top + height
            )
            if near_bottom:
                if self.toolbar.winfo_manager() != 'place':
                    # Overlay the existing controls without resizing the video.
                    self.toolbar.place(in_=self.video_frame, relx=0, rely=1, relwidth=1, anchor='sw')
                    self.toolbar.lift()
            elif self.toolbar.winfo_manager() == 'place':
                self.toolbar.place_forget()
            self._fullscreen_after_id = self.after(100, self._sync_fullscreen_controls)

        def _schedule_video_redraw(self, _event=None) -> None:
            if self._closing:
                return
            if self._video_resize_after_id is not None:
                self.after_cancel(self._video_resize_after_id)
            self._video_resize_after_id = self.after(60, self._redraw_video)

        def _redraw_video(self) -> None:
            self._video_resize_after_id = None
            if not self._closing and self._last_pil_image is not None:
                self._show_display_image(self._last_pil_image, hide_overlay=False)

        def _save_screenshot(self) -> None:
            if self._last_pil_image is None:
                self._set_state('No video', 'No frame available for screenshot')
                return
            stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            path = self.config_data.paths.screenshots_dir / f'screenshot_{self._current_quality}_{stamp}.png'
            self._last_pil_image.save(path)
            self._set_state(self._status if self._status == 'Live' else 'Idle', f'Screenshot saved: {path.name}')

        def _stop_current_session(self) -> None:
            self._stop_event.set()
            self._ptz_queue.clear()
            self._hide_ptz_panel()
            self._pending_frames.clear()
            self._payload_activity_seen = False
            self._video_material_seen = False
            self._rendered_frame_count = 0
            self._recording_playback_started_at = 0.0
            decoder = self._decoder
            self._decoder = None
            audio_player = self._audio_player
            self._audio_player = None
            if decoder is not None:
                threading.Thread(
                    target=decoder.stop,
                    daemon=True,
                    name='xmplayer-decoder-stop',
                ).start()
            if audio_player is not None:
                threading.Thread(
                    target=audio_player.stop,
                    daemon=True,
                    name='xmplayer-audio-stop',
                ).start()

        def _start_session(self, *, reconnect: bool, recording: RecordingItem | None = None) -> None:
            if self._closing:
                return
            if not shutil.which(self.config_data.ffmpeg_path):
                from tkinter import messagebox

                message = (
                    'FFmpeg is required to play live video and recordings.\n\n'
                    f'FFmpeg not found: {self.config_data.ffmpeg_path}\n\n'
                    'Install FFmpeg or set ffmpeg_path to its executable in the configuration.'
                )
                self._set_state('Error', 'FFmpeg not found. Video playback is unavailable.')
                self._update_controls()
                messagebox.showerror('Video playback unavailable', message, parent=self)
                return
            if reconnect and self._worker_alive():
                self._cancel_restart_timer()
                self._session_generation += 1
                self._current_recording = recording
                self._restart_pending = True
                self._stop_pending = False
                self._stop_current_session()
                self._set_state('Retrying', 'Restarting recording playback' if recording is not None else 'Restarting live chain')
                self._schedule_restart()
                self._update_controls()
                return
            if self._worker_alive() or self._restart_pending or self._restart_after_id is not None:
                return
            self._cancel_restart_timer()
            self._stop_pending = False
            self._session_generation += 1
            self._ptz_queue.clear()
            self._hide_ptz_panel()
            generation = self._session_generation
            stop_event = threading.Event()
            self._stop_event = stop_event
            self._capture_artifacts = None
            self._pending_frames.clear()
            self._payload_activity_seen = False
            self._video_material_seen = False
            self._rendered_frame_count = 0
            self._recording_playback_started_at = 0.0
            self._current_recording = recording
            self._set_state('Connecting', 'Preparing recording playback' if recording is not None else 'Preparing live chain')
            quality = self._current_quality
            self._worker = threading.Thread(target=self._session_worker, args=(generation, quality, stop_event, recording), daemon=True)
            self._worker.start()
            self._update_controls()

        def _restart_when_idle(self) -> None:
            if self._closing:
                return
            if self._worker_alive():
                self._restart_after_id = self.after(150, self._restart_when_idle)
                return
            self._restart_after_id = None
            if not self._restart_pending:
                self._update_controls()
                return
            self._restart_pending = False
            self._start_session(reconnect=False, recording=self._current_recording)

        def _session_worker(
            self,
            generation: int,
            quality: str,
            master_stop_event: threading.Event,
            recording: RecordingItem | None = None,
        ) -> None:
            decoder: FFmpegStreamDecoder | None = None
            audio_player: G711AudioPlayer | None = None
            try:
                decoder = FFmpegStreamDecoder(self.config_data.ffmpeg_path)
                self._decoder = decoder
                audio_player = G711AudioPlayer()
                if audio_player.start():
                    self._audio_player = audio_player
                else:
                    audio_player = None
                decoder.start(
                    on_frame=lambda image: (
                        None
                        if master_stop_event.is_set() or self._closing or generation != self._session_generation
                        else self._ui_queue.put(('frame', image.copy(), generation))
                    ),
                    output_fps=self.config_data.playback_fps if recording is not None else None,
                )
                reconnect_index = 0
                while not master_stop_event.is_set():
                    reconnect_index += 1
                    assembler = LiveXStreamHevcAssembler()
                    hevc_chunk_count = 0
                    last_media_activity_at = 0.0
                    session_stop_event = threading.Event()

                    def _idle_watchdog() -> None:
                        while not session_stop_event.is_set():
                            if master_stop_event.is_set():
                                session_stop_event.set()
                                return
                            if last_media_activity_at > 0 and (hevc_chunk_count > 0 or self._payload_activity_seen):
                                idle_limit = self._session_idle_reconnect_seconds
                                if recording is not None:
                                    idle_limit = max(30.0, idle_limit * 8.0)
                                if self._rendered_frame_count <= 0:
                                    idle_limit = max(idle_limit * 4.0, 8.0)
                                if (time.time() - last_media_activity_at) >= idle_limit:
                                    session_stop_event.set()
                                    return
                            time.sleep(0.25)

                    watchdog_thread = threading.Thread(
                        target=_idle_watchdog,
                        daemon=True,
                        name='xmplayer-live-idle-watchdog',
                    )
                    watchdog_thread.start()

                    def _on_data_frame_payload(payload: bytes, vekey1: str) -> bool:
                        nonlocal hevc_chunk_count, last_media_activity_at
                        if master_stop_event.is_set() or session_stop_event.is_set() or generation != self._session_generation:
                            return False
                        if vekey1:
                            assembler.set_random_str(vekey1)
                        hevc_bytes, audio_bytes = assembler.push_media_payload(payload)
                        if audio_bytes and audio_player is not None:
                            audio_player.write_g711(audio_bytes)
                        saw_media_activity = bool(hevc_bytes)
                        if saw_media_activity:
                            self._payload_activity_seen = True
                            last_media_activity_at = time.time()
                            if self._rendered_frame_count <= 0:
                                self._queue_status(generation, 'Buffering', 'Receiving video')
                            if decoder.write(hevc_bytes):
                                last_media_activity_at = time.time()
                                self._video_material_seen = True
                                hevc_chunk_count += 1
                                if self._rendered_frame_count <= 0:
                                    self._queue_status(generation, 'Buffering', 'Decoding video')
                                return True
                            session_stop_event.set()
                            return False
                        return False

                    capture = None
                    try:
                        if recording is None:
                            capture = run_monitor_live_stream(
                                self.config_data,
                                quality=quality,
                                stop_event=session_stop_event,
                                status_callback=lambda state, detail: self._queue_status(generation, state, detail),
                                data_frame_callback=_on_data_frame_payload,
                                ptz_queue=self._ptz_queue,
                            )
                        else:
                            capture = run_recording_playback_stream(
                                self.config_data,
                                recording,
                                stop_event=session_stop_event,
                                status_callback=lambda state, detail: self._queue_status(generation, state, detail),
                                data_frame_callback=_on_data_frame_payload,
                            )
                    except MonitorCancelled:
                        if master_stop_event.is_set():
                            raise
                    if capture is not None:
                        if generation == self._session_generation:
                            self._ui_queue.put(('capture', capture, generation))
                    if master_stop_event.is_set():
                        return
                    session_stop_event.set()
                    if hevc_chunk_count > 0:
                        if recording is not None:
                            self._queue_status(generation, 'Idle', 'Recording playback finished')
                            return
                        continue
                    if capture is None:
                        self._queue_status(generation, 'No video', 'Playback session ended before capture was produced' if recording is not None else 'Live session ended before capture was produced')
                        return
                    failure_detail = describe_capture_failure(capture.result)
                    if failure_detail:
                        self._queue_status(generation, 'No video', failure_detail)
                        return
                    second_status, second_data_frames = _summarize_second_probe(capture.result)
                    if second_data_frames <= 0:
                        detail = 'No video in recording playback' if recording is not None else 'No video in live session'
                        if second_status:
                            detail += f' ({second_status})'
                        if reconnect_index < self.config_data.attempts:
                            self._queue_status(generation, 'Retrying', detail)
                            continue
                        self._queue_status(generation, 'No video', detail)
                        return
            except MonitorCancelled:
                self._queue_status(generation, 'Idle', 'Playback stopped')
            except MonitorCaptureError as exc:
                message = str(exc)
                if 'no_plain_handoff_data_frames' in message:
                    self._queue_status(generation, 'No video', 'Second handoff did not produce media frames')
                else:
                    self._queue_status(generation, 'Error', message)
            except Exception as exc:
                detail = f'{exc}\n\n{traceback.format_exc(limit=4)}'
                self._queue_status(generation, 'Error', detail)
            finally:
                if audio_player is not None:
                    audio_player.stop()
                if self._audio_player is audio_player:
                    self._audio_player = None
                if decoder is not None:
                    decoder.stop()
                if self._decoder is decoder:
                    self._decoder = None

        def _prepare_display_image(self, pil_image):
            if self._video_layout == 'horizontal':
                return _stacked_split_view(pil_image, self.Image)
            return pil_image

        def _show_display_image(self, display_source, *, hide_overlay: bool = True) -> None:
            self._last_pil_image = display_source
            padding = 0 if self._fullscreen else 8
            box_w = max(self.video_frame.winfo_width() - padding, 1)
            box_h = max(self.video_frame.winfo_height() - padding, 1)
            width, height = _fit_size(display_source.width, display_source.height, box_w, box_h)
            display_image = display_source.resize((width, height)) if (width, height) != (display_source.width, display_source.height) else display_source
            self._last_tk_image = self.ImageTk.PhotoImage(display_image)
            self.video_label.configure(image=self._last_tk_image)
            self.video_mode_badge.lift()
            if self._ptz_panel_visible:
                self.ptz_panel.lift()
            if hide_overlay:
                self.overlay.place_forget()

        def _render_frame(self, pil_image) -> None:
            self._last_source_image = pil_image
            display_source = self._prepare_display_image(pil_image)
            self._rendered_frame_count += 1
            if self._current_recording is not None and self._recording_playback_started_at <= 0:
                self._recording_playback_started_at = time.monotonic()
            self._show_display_image(display_source)

        def _recording_duration_elapsed(self) -> bool:
            recording = self._current_recording
            if recording is None or self._recording_playback_started_at <= 0:
                return False
            duration = max(int(recording.duration_seconds or 0), 0)
            if duration <= 0:
                return False
            return (time.monotonic() - self._recording_playback_started_at) >= (duration + 0.75)

        def _finish_recording_playback(self) -> None:
            self._cancel_restart_timer()
            self._restart_pending = False
            self._session_generation += 1
            self._current_recording = None
            self._stop_pending = self._worker_alive()
            self._stop_current_session()
            self._set_state('Idle', 'Recording playback finished')
            self._update_controls()

        def _playback_tick(self) -> None:
            if self._closing:
                return
            try:
                if self._pending_frames:
                    frame = self._pending_frames.popleft()
                    if self._status != 'Live':
                        self._set_state('Live', 'Streaming')
                    self._render_frame(frame)
                    if self._recording_duration_elapsed():
                        self._finish_recording_playback()
                        return
            finally:
                if not self._closing:
                    self._playback_after_id = self.after(self._frame_interval_ms, self._playback_tick)

        def _poll_queue(self) -> None:
            if self._closing:
                return
            processed = 0
            queue_drained = False
            try:
                while processed < 120:
                    kind, payload, extra = self._ui_queue.get_nowait()
                    processed += 1
                    if kind == 'status':
                        generation = None
                        detail = ''
                        if isinstance(extra, dict):
                            detail = str(extra.get('detail') or '')
                            generation = extra.get('generation')
                        else:
                            detail = str(extra or '')
                        if generation is not None and generation != self._session_generation:
                            continue
                        self._handle_service_status(str(payload), detail)
                    elif kind == 'frame':
                        if extra is not None and extra != self._session_generation:
                            continue
                        self._pending_frames.append(payload)
                        frame_queue_limit = 90
                        if self._current_recording is not None:
                            frame_queue_limit = max(240, int(self.config_data.playback_fps * 60))
                        while len(self._pending_frames) > frame_queue_limit:
                            self._pending_frames.popleft()
                    elif kind == 'capture':
                        if extra is not None and extra != self._session_generation:
                            continue
                        self._capture_artifacts = payload
                    elif kind == 'recordings':
                        generation = extra.get('generation') if isinstance(extra, dict) else None
                        if generation is not None and generation != self._recordings_generation:
                            continue
                        meta = extra.get('meta') if isinstance(extra, dict) and isinstance(extra.get('meta'), dict) else {}
                        self._handle_recordings_result(payload if isinstance(payload, list) else [], meta)
                    elif kind == 'recordings_error':
                        generation = extra.get('generation') if isinstance(extra, dict) else None
                        if generation is not None and generation != self._recordings_generation:
                            continue
                        self._handle_recordings_error(str(payload))
                    elif kind == 'messages':
                        generation = extra.get('generation') if isinstance(extra, dict) else None
                        if generation is not None and generation != self._messages_generation:
                            continue
                        meta = extra.get('meta') if isinstance(extra, dict) and isinstance(extra.get('meta'), dict) else {}
                        thumbs = extra.get('thumbs') if isinstance(extra, dict) and isinstance(extra.get('thumbs'), dict) else {}
                        self._handle_messages_result(payload if isinstance(payload, list) else [], meta, thumbs)
                    elif kind == 'messages_thumbs':
                        generation = extra.get('generation') if isinstance(extra, dict) else None
                        if generation is not None and generation != self._messages_generation:
                            continue
                        thumbs = extra.get('thumbs') if isinstance(extra, dict) and isinstance(extra.get('thumbs'), dict) else {}
                        self._apply_message_thumbnails(thumbs)
                    elif kind == 'messages_error':
                        generation = extra.get('generation') if isinstance(extra, dict) else None
                        if generation is not None and generation != self._messages_generation:
                            continue
                        self._handle_messages_error(str(payload))
            except queue.Empty:
                queue_drained = True
                pass
            self._update_controls()
            if not self._closing:
                self._poll_after_id = self.after(80 if queue_drained else 1, self._poll_queue)

        def _on_close(self) -> None:
            self._closing = True
            if self._wifi_dialog is not None and self._wifi_dialog.winfo_exists():
                self._wifi_dialog.close()
            self._close_message_image()
            self._cancel_restart_timer()
            self._restart_pending = False
            self._session_generation += 1
            self._recordings_generation += 1
            self._messages_generation += 1
            self._stop_current_session()
            worker = self._worker
            if worker is not None and worker.is_alive():
                worker.join(timeout=1.0)
            for after_id in (
                self._poll_after_id,
                self._playback_after_id,
                self._restart_after_id,
                self._startup_progress_after_id,
                self._fullscreen_after_id,
                self._video_resize_after_id,
            ):
                if after_id:
                    try:
                        self.after_cancel(after_id)
                    except Exception:
                        pass
            try:
                self.withdraw()
            except Exception:
                pass
            try:
                self.quit()
            except Exception:
                pass
            try:
                self.destroy()
            except Exception:
                pass

    app = MonitorApp()
    app.mainloop()
    return 2 if app._restart_app else 0


def main() -> int:
    while True:
        result = _run_gui_session()
        if result != 2:
            return result
