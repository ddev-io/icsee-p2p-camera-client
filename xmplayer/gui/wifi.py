from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable

from ..config.loader import MonitorConfig
from ..core.service import MonitorCancelled
from ..core.wifi import CameraWifi, build_wifi_config, read_camera_wifi, save_camera_wifi, wifi_network_security


class CameraWifiDialog(tk.Toplevel):
    def __init__(self, parent, config: MonitorConfig, palette: dict[str, str], *, before_save: Callable[[], None]) -> None:
        super().__init__(parent)
        self.config_data = config
        self.palette = palette
        self.before_save = before_save
        self._settings: CameraWifi | None = None
        self._busy = False
        self._closed = False
        self._stop_event = threading.Event()
        self._results: queue.Queue = queue.Queue()
        self._poll_id: str | None = None
        self.title(f'Camera Wi-Fi - {config.device_name}')
        self.geometry('760x560')
        self.minsize(600, 480)
        self.transient(parent)
        self.configure(bg=palette['panel'])
        self.protocol('WM_DELETE_WINDOW', self.close)

        self.current_var = tk.StringVar(value='Current network: loading...')
        self.ssid_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.security_var = tk.StringVar(value='Select a network')
        self.show_password_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value='')
        body = tk.Frame(self, bg=palette['panel'], padx=20, pady=18)
        body.pack(fill='both', expand=True)
        body.columnconfigure(0, weight=1)
        # Only the network list absorbs height changes; reserve space for the
        # password, status and buttons even when the window is made smaller.
        body.rowconfigure(3, weight=1)
        self._label(body, 'Camera Wi-Fi', font=('Segoe UI Semibold', 16)).grid(row=0, column=0, sticky='w')
        self._label(body, variable=self.current_var).grid(row=1, column=0, sticky='w', pady=(6, 12))
        self._label(body, 'Networks visible to the camera').grid(row=2, column=0, sticky='w')

        style = ttk.Style(self)
        style.configure('XmWifi.Treeview', background='white', fieldbackground='white',
                        foreground='black', rowheight=28, font=('Segoe UI', 10))
        style.map('XmWifi.Treeview', background=[('selected', '#0078d7'), ('!selected', 'white')],
                  foreground=[('selected', 'white'), ('!selected', 'black')])
        list_frame = tk.Frame(body, bg=palette['panel'])
        list_frame.grid(row=3, column=0, sticky='nsew', pady=(6, 14))
        self.networks_tree = ttk.Treeview(list_frame, columns=('ssid', 'security', 'signal', 'channel'),
                                         show='headings', selectmode='browse', height=5, style='XmWifi.Treeview')
        for name, label, width in (('ssid', 'Network', 280), ('security', 'Security', 160),
                                   ('signal', 'Signal', 85), ('channel', 'Channel', 70)):
            self.networks_tree.heading(name, text=label)
            self.networks_tree.column(name, width=width, minwidth=50, stretch=name == 'ssid')
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.networks_tree.yview)
        self.networks_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.networks_tree.pack(side='left', fill='both', expand=True)
        self.networks_tree.bind('<<TreeviewSelect>>', self._select_network)

        form = tk.Frame(body, bg=palette['panel'])
        form.grid(row=4, column=0, sticky='ew')
        form.columnconfigure(1, weight=1)
        self._label(form, 'Selected network').grid(row=0, column=0, sticky='w', padx=(0, 14), pady=5)
        self.ssid_entry = tk.Entry(form, textvariable=self.ssid_var, state='readonly', font=('Segoe UI', 10))
        self.ssid_entry.grid(row=0, column=1, sticky='ew', pady=5, ipady=3)
        self._label(form, 'Security').grid(row=1, column=0, sticky='w', pady=5)
        self._label(form, variable=self.security_var).grid(row=1, column=1, sticky='w', pady=5)
        self._label(form, 'Wi-Fi password').grid(row=2, column=0, sticky='w', pady=5)
        self.password_entry = tk.Entry(form, textvariable=self.password_var, show='*', font=('Segoe UI', 10))
        self.password_entry.grid(row=2, column=1, sticky='ew', pady=5, ipady=3)
        self.show_password = tk.Checkbutton(form, text='Show password', variable=self.show_password_var,
                                           command=self._toggle_password, bg=palette['panel'], fg=palette['text'],
                                           selectcolor=palette['surface'], activebackground=palette['panel'])
        self.show_password.grid(row=3, column=1, sticky='w')
        hint = self._label(body, 'Choose a network from the camera list. Saving will temporarily disconnect the camera.',
                           wraplength=560, justify='left')
        hint.grid(row=5, column=0, sticky='w', pady=(12, 4))
        self.status_label = self._label(body, variable=self.status_var, wraplength=560, justify='left',
                                        height=3, anchor='nw')
        self.status_label.grid(row=6, column=0, sticky='ew', pady=(0, 12))

        actions = tk.Frame(body, bg=palette['panel'])
        actions.grid(row=7, column=0, sticky='ew')
        self.refresh_button = self._button(actions, 'Refresh networks', self.refresh)
        self.refresh_button.pack(side='left')
        self.apply_button = self._button(actions, 'Connect camera', self._apply, accent=True)
        self.apply_button.pack(side='right')
        self.close_button = self._button(actions, 'Close', self.close)
        self.close_button.pack(side='right', padx=(0, 8))
        # Account for the user's font/DPI settings instead of clipping the
        # footer inside a fixed-height window. Keep at least two list rows.
        self.update_idletasks()
        minimum_height = self.winfo_reqheight() - list_frame.winfo_reqheight() + 84
        self.minsize(600, max(480, minimum_height))
        self.geometry(f'760x{max(560, self.winfo_reqheight())}')
        def resize_text(event):
            width = max(1, event.width - 40)
            hint.configure(wraplength=width)
            self.status_label.configure(wraplength=width)
        body.bind('<Configure>', resize_text)
        self._poll_id = self.after(80, self._poll)
        self.refresh()

    def _label(self, parent, text='', *, variable=None, **kwargs):
        return tk.Label(parent, text=text, textvariable=variable, bg=self.palette['panel'],
                        fg=self.palette['text'], **kwargs)

    def _button(self, parent, text, command, *, accent=False):
        return tk.Button(parent, text=text, command=command, relief='flat', padx=14, pady=8,
                         bg=self.palette['accent'] if accent else self.palette['border'], fg='white',
                         activebackground=self.palette['border'], activeforeground='white',
                         disabledforeground=self.palette['muted'], font=('Segoe UI', 10))

    def _update_controls(self) -> None:
        network = self._selected_network()
        ready = (not self._busy and self._settings is not None and bool(self._settings._config)
                 and network is not None and wifi_network_security(network) != 'Unsupported')
        self.refresh_button.configure(state='disabled' if self._busy else 'normal')
        self.apply_button.configure(state='normal' if ready else 'disabled')
        self.password_entry.configure(state='normal' if ready and self.security_var.get() == 'WPA2' else 'disabled')
        self.show_password.configure(state='disabled' if self._busy else 'normal')

    def _toggle_password(self) -> None:
        self.password_entry.configure(show='' if self.show_password_var.get() else '*')

    def _selected_network(self):
        selection = self.networks_tree.selection()
        if self._settings is None or not selection:
            return None
        index = int(selection[0])
        return self._settings.networks[index] if 0 <= index < len(self._settings.networks) else None

    def _select_network(self, _event=None) -> None:
        network = self._selected_network()
        if self._busy or network is None:
            return
        self.ssid_var.set(network.ssid)
        self.password_var.set('')
        security = wifi_network_security(network)
        opened = security == 'Open'
        self.security_var.set(security)
        self.status_var.set('Enter the password for this network.' if not opened else 'This network does not require a password.')
        if security == 'Unsupported':
            self.status_var.set('This camera setting supports WPA2 or open networks. Choose a compatible network.')
        elif network.channel > 14:
            self.status_var.set('This network uses 5 GHz. Make sure the camera supports it before connecting.')
        self._update_controls()

    def _run(self, kind: str, operation) -> None:
        self._busy = True
        self._update_controls()
        def worker():
            try:
                self._results.put((kind, operation()))
            except MonitorCancelled:
                pass
            except Exception as exc:
                # Do not include credentials, payloads or tracebacks in UI/logs.
                self._results.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True, name=f'xmplayer-wifi-{kind}').start()

    def refresh(self) -> None:
        if self._closed or self._busy:
            return
        if self._settings is not None:
            self._settings._config.clear()
        self._settings = None
        self.networks_tree.delete(*self.networks_tree.get_children())
        self.ssid_var.set('')
        self.security_var.set('Select a network')
        self.password_var.set('')
        self.status_var.set('Reading camera settings and scanning networks...')
        self._run('loaded', lambda: read_camera_wifi(self.config_data, stop_event=self._stop_event))

    def _apply(self) -> None:
        settings = self._settings
        network = self._selected_network()
        if self._closed or self._busy or settings is None or network is None:
            return
        ssid = network.ssid
        password = self.password_var.get() if self.security_var.get() == 'WPA2' else ''
        try:
            if wifi_network_security(network) == 'Unsupported':
                raise ValueError('Choose a WPA2/AES or open network from the camera list.')
            if self.security_var.get() == 'WPA2' and not password:
                raise ValueError('Enter the Wi-Fi password for the selected network.')
            check = build_wifi_config(settings._config, ssid, password)
            check.clear()
        except ValueError as exc:
            messagebox.showerror('Camera Wi-Fi', str(exc), parent=self)
            return
        if not messagebox.askokcancel('Connect camera',
                f'Connect {self.config_data.device_name} to "{ssid}"?\n\n'
                'The camera will disconnect while changing networks. Wait for it to reconnect before starting video.',
                parent=self):
            return
        self.before_save()
        self.password_var.set('')
        self.status_var.set('Sending Wi-Fi settings to the camera...')
        def save():
            try:
                save_camera_wifi(self.config_data, settings, network, password, stop_event=self._stop_event)
            except Exception as exc:
                # Some transport errors can contain request text. Redact both
                # the password and its JSON representation before displaying.
                import json
                message = str(exc)
                if password:
                    for secret in (password, json.dumps(password, ensure_ascii=False)[1:-1]):
                        message = message.replace(secret, '[redacted]')
                raise RuntimeError(message) from None
            return ssid
        self._run('saved', save)

    def _poll(self) -> None:
        if self._closed:
            return
        try:
            kind, result = self._results.get_nowait()
        except queue.Empty:
            pass
        else:
            self._busy = False
            if kind == 'loaded':
                self._settings = result
                self.current_var.set(f'Current network: {result.current_ssid or "not configured"}')
                for i, network in enumerate(result.networks):
                    self.networks_tree.insert('', 'end', iid=str(i), values=(
                        network.ssid, network.auth, network.signal, network.channel or ''))
                self.status_var.set(result.scan_error or (
                    f'Found {len(result.networks)} networks. Choose one from the list.' if result.networks else 'No networks found. Refresh to scan again.'))
            elif kind == 'saved':
                self.status_var.set('Camera acknowledged the Wi-Fi settings. Wait for it to reconnect, then refresh to check the current network.')
                self.current_var.set('Current network: waiting for camera to reconnect')
            else:
                self.status_var.set(result)
            self._update_controls()
        self._poll_id = self.after(80, self._poll)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop_event.set()
        self.password_var.set('')
        if self._settings is not None:
            self._settings._config.clear()
        if self._poll_id is not None:
            self.after_cancel(self._poll_id)
        self.destroy()
