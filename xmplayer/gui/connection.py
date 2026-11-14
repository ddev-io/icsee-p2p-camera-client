from pathlib import Path
import tkinter as tk
from tkinter import messagebox

from ..config.connection import read_account_credentials, save_connection_settings
from ..config.loader import MonitorConfig


class ConnectionDialog(tk.Toplevel):
    def __init__(self, parent, config: MonitorConfig):
        super().__init__(parent)
        self.config_data = config
        self.saved_path: Path | None = None
        self.title('Camera connection')
        self.configure(bg='#f4f6f8')
        self.geometry('530x540')
        self.minsize(500, 520)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        if parent.winfo_viewable():
            self.transient(parent)

        account, account_password = read_account_credentials(config.cloud_login_file)
        self.mode_var = tk.StringVar(value=config.connection_mode)
        self.account_var = tk.StringVar(value=account)
        self.account_password_var = tk.StringVar(value=account_password)
        self.cloud_id_var = tk.StringVar(value=config.cloud_id or config.device_id)
        self.device_user_var = tk.StringVar(value=config.device_username)
        self.device_password_var = tk.StringVar(value=config.device_password)
        self.show_password_var = tk.BooleanVar(value=False)

        body = tk.Frame(self, bg='#f4f6f8', padx=26, pady=22)
        body.grid(row=0, column=0, sticky='nsew')
        tk.Label(body, text='Connect your camera', bg='#f4f6f8', fg='#18212b',
                 font=('Segoe UI Semibold', 15)).pack(anchor='w')
        choices = tk.Frame(body, bg='#f4f6f8')
        choices.pack(fill='x', pady=(16, 10))
        for value, label in (('account', 'iCSee / XM account'), ('cloud_id', 'Cloud ID')):
            tk.Radiobutton(choices, text=label, value=value, variable=self.mode_var,
                           command=self._select_mode, bg='#f4f6f8', fg='#18212b',
                           activebackground='#f4f6f8', font=('Segoe UI', 10)).pack(side='left', padx=(0, 18))
        self.description_var = tk.StringVar()
        tk.Label(body, textvariable=self.description_var, bg='#f4f6f8', fg='#52606d',
                 font=('Segoe UI', 10), wraplength=450, justify='left',
                 height=3, anchor='nw').pack(fill='x', pady=(0, 10))
        self.forms = tk.Frame(body, bg='#f4f6f8')
        self.forms.pack(fill='both', expand=True)
        self.account_form = tk.Frame(self.forms, bg='#f4f6f8')
        self.cloud_id_form = tk.Frame(self.forms, bg='#f4f6f8')
        self.account_entry = self._field(self.account_form, 'Username or email', self.account_var)
        self.account_password_entry = self._field(self.account_form, 'Account password', self.account_password_var, password=True)
        self.cloud_id_entry = self._field(self.cloud_id_form, 'Cloud ID', self.cloud_id_var)
        self.device_user_entry = self._field(self.cloud_id_form, 'Camera username', self.device_user_var)
        self.device_password_entry = self._field(self.cloud_id_form, 'Camera password', self.device_password_var, password=True)
        tk.Checkbutton(body, text='Show password', variable=self.show_password_var,
                       command=self._show_password, bg='#f4f6f8', fg='#34414d',
                       font=('Segoe UI', 9)).pack(anchor='w', pady=(8, 4))
        tk.Label(body, text='Sign-in details are saved on this computer.',
                 bg='#f4f6f8', fg='#52606d', font=('Segoe UI', 9)).pack(anchor='w')
        actions = tk.Frame(self, bg='#f4f6f8', padx=26, pady=18)
        actions.grid(row=1, column=0, sticky='ew')
        self.cancel_button = tk.Button(actions, text='Cancel', command=self.destroy, width=12)
        self.cancel_button.pack(side='right')
        self.save_button = tk.Button(actions, text='Continue', command=self._submit, width=12, default='active')
        self.save_button.pack(side='right', padx=(0, 8))
        self.bind('<Return>', lambda _event: self._submit())
        self.bind('<Escape>', lambda _event: self.destroy())
        self._select_mode()

    def _field(self, parent, label, variable, password=False):
        tk.Label(parent, text=label, bg='#f4f6f8', fg='#34414d', font=('Segoe UI', 10)).pack(anchor='w')
        entry = tk.Entry(parent, textvariable=variable, bg='white', fg='#18212b',
                         insertbackground='#18212b', font=('Segoe UI', 11),
                         show='*' if password else '', relief='solid', bd=1)
        entry.pack(fill='x', pady=(5, 12), ipady=5)
        return entry

    def _select_mode(self):
        self.account_form.pack_forget()
        self.cloud_id_form.pack_forget()
        if self.mode_var.get() == 'cloud_id':
            self.cloud_id_form.pack(fill='x')
            self.description_var.set('Use the camera Cloud ID and its own username and password. An app account is not required.')
            self.cloud_id_entry.focus_set()
        else:
            self.account_form.pack(fill='x')
            self.description_var.set('Use the account from the iCSee or XM mobile app. The camera will be selected from your account.')
            self.account_entry.focus_set()

    def _show_password(self):
        show = '' if self.show_password_var.get() else '*'
        self.account_password_entry.configure(show=show)
        self.device_password_entry.configure(show=show)

    def _submit(self):
        try:
            self.saved_path = save_connection_settings(
                self.config_data, mode=self.mode_var.get(), account=self.account_var.get(),
                account_password=self.account_password_var.get(), cloud_id=self.cloud_id_var.get(),
                device_username=self.device_user_var.get(), device_password=self.device_password_var.get())
        except (ValueError, OSError) as exc:
            messagebox.showerror('Connection details', str(exc), parent=self)
            return
        self.destroy()


def prompt_for_connection(config: MonitorConfig, parent=None) -> Path | None:
    root = parent
    own_root = root is None
    if own_root:
        root = tk.Tk()
        root.withdraw()
    dialog = ConnectionDialog(root, config)
    dialog.grab_set()
    root.wait_window(dialog)
    path = dialog.saved_path
    if own_root:
        root.destroy()
    return path
