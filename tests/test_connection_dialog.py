import json
from pathlib import Path
import tempfile
import tkinter as tk
import unittest
from unittest.mock import patch

from xmplayer.config.loader import load_monitor_config
from xmplayer.gui.connection import ConnectionDialog


class ConnectionDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.path = root / 'desktop_monitor.json'
        self.path.write_text(json.dumps({'cloud_login_file': str(root / 'missing-login.txt'),
                                        'paths': {'screenshots_dir': str(root / 'screens')}}))
        self.config = load_monitor_config(self.path)
        self.dialog = ConnectionDialog(self.root, self.config)
        self.dialog.withdraw()

    def tearDown(self):
        if self.dialog.winfo_exists():
            self.dialog.destroy()
        self.root.update()
        self.temp.cleanup()

    def test_mode_switch_shows_only_relevant_fields(self):
        self.assertEqual(self.dialog.account_form.winfo_manager(), 'pack')
        self.assertEqual(self.dialog.cloud_id_form.winfo_manager(), '')
        self.dialog.mode_var.set('cloud_id')
        self.dialog._select_mode()
        self.assertEqual(self.dialog.account_form.winfo_manager(), '')
        self.assertEqual(self.dialog.cloud_id_form.winfo_manager(), 'pack')
        self.assertIn('account is not required', self.dialog.description_var.get())
        self.assertEqual(self.dialog.device_password_entry.cget('show'), '*')
        self.assertEqual(self.dialog.cloud_id_entry.cget('bg'), 'white')

    def test_cloud_id_submit_accepts_blank_camera_password(self):
        self.dialog.mode_var.set('cloud_id')
        self.dialog.cloud_id_var.set('CAMERA123456789012345')
        self.dialog.device_user_var.set('admin')
        self.dialog.device_password_var.set('')
        self.dialog._submit()
        saved = load_monitor_config(self.dialog.saved_path)
        self.assertEqual(saved.connection_mode, 'cloud_id')
        self.assertEqual(saved.device_password, '')
        self.assertFalse(self.config.cloud_login_file.exists())

    def test_invalid_cloud_id_keeps_dialog_open_and_shows_error(self):
        self.dialog.mode_var.set('cloud_id')
        self.dialog.cloud_id_var.set('invalid&id')
        with patch('xmplayer.gui.connection.messagebox.showerror') as error:
            self.dialog._submit()
        error.assert_called_once()
        self.assertIsNone(self.dialog.saved_path)
        self.assertTrue(self.dialog.winfo_exists())

    def test_cancel_does_not_write_configuration(self):
        self.dialog.destroy()
        self.assertFalse((self.path.parent / 'desktop_monitor.local.json').exists())


if __name__ == '__main__':
    unittest.main()
