import copy
import json
import time
import tkinter as tk
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from xmplayer.core.wifi import CameraWifi, WifiNetwork
from xmplayer.gui import wifi


class WifiDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        cls.palette = json.loads((Path(__file__).resolve().parents[1] / 'xmplayer/assets/monitor_palette.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.networks = [WifiNetwork('First', 'WPA2PSK', 'AES', 6, '-50'),
                         WifiNetwork('Open', 'OPEN', 'NONE', 11, '-70'),
                         WifiNetwork('WEP', 'SHARED', 'WEP', 1, '-60')]
        self.settings = CameraWifi('Current', self.networks, _config={'SSID': 'Current', 'Keys': 'old-secret'})
        self.read_patch = patch.object(wifi, 'read_camera_wifi', side_effect=lambda *a, **kw: copy.deepcopy(self.settings))
        self.read_patch.start()
        self.before_save = Mock()
        self.dialog = wifi.CameraWifiDialog(self.root, SimpleNamespace(device_name='Test camera'), self.palette,
                                            before_save=self.before_save)
        self.wait_until(lambda: not self.dialog._busy)

    def tearDown(self):
        self.dialog.close()
        self.read_patch.stop()
        self.root.update()

    def wait_until(self, predicate):
        deadline = time.monotonic() + 3
        while not predicate() and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.assertTrue(predicate())

    def select(self, index):
        self.dialog.networks_tree.selection_set(str(index))
        self.root.update()

    def test_name_is_readonly_and_current_network_does_not_count_as_selection(self):
        self.assertEqual(str(self.dialog.ssid_entry['state']), 'readonly')
        self.assertEqual(self.dialog.ssid_var.get(), '')
        self.assertEqual(str(self.dialog.apply_button['state']), 'disabled')
        self.assertIn('Current', self.dialog.current_var.get())

    def test_selected_row_sets_name_and_security_and_clears_previous_password(self):
        self.select(0)
        self.dialog.password_var.set('secret-for-first')
        self.select(1)
        self.assertEqual(self.dialog.ssid_var.get(), 'Open')
        self.assertEqual(self.dialog.security_var.get(), 'Open')
        self.assertEqual(self.dialog.password_var.get(), '')
        self.assertEqual(str(self.dialog.password_entry['state']), 'disabled')

    def test_unsupported_network_cannot_be_connected(self):
        self.select(2)
        self.assertEqual(str(self.dialog.apply_button['state']), 'disabled')

    def test_empty_scan_disables_connect(self):
        self.settings.networks = []
        self.dialog.refresh()
        self.wait_until(lambda: not self.dialog._busy)
        self.assertEqual(self.dialog.networks_tree.get_children(), ())
        self.assertEqual(str(self.dialog.apply_button['state']), 'disabled')

    def test_refresh_discards_selection_and_password(self):
        self.select(0)
        self.dialog.password_var.set('secret-for-first')
        self.dialog.refresh()
        self.wait_until(lambda: not self.dialog._busy)
        self.assertEqual(self.dialog.ssid_var.get(), '')
        self.assertEqual(self.dialog.password_var.get(), '')
        self.assertEqual(str(self.dialog.apply_button['state']), 'disabled')

    def test_cancel_does_not_stop_video_or_send_settings(self):
        self.select(0)
        self.dialog.password_var.set('test-password')
        with patch.object(wifi.messagebox, 'askokcancel', return_value=False), \
             patch.object(wifi, 'save_camera_wifi') as save:
            self.dialog._apply()
            save.assert_not_called()
            self.before_save.assert_not_called()

    def test_apply_uses_selected_row_and_clears_password(self):
        self.select(0)
        self.dialog.password_var.set('test-password')
        sent = {}
        def capture(_config, _name, _cmd, *, body, **_kwargs):
            sent.update(copy.deepcopy(body))
            return {'Ret': 100}
        with patch.object(wifi.messagebox, 'askokcancel', return_value=True), \
             patch('xmplayer.core.wifi._command', side_effect=capture):
            self.dialog._apply()
            self.wait_until(lambda: not self.dialog._busy)
            self.before_save.assert_called_once()
            self.assertEqual(self.dialog.password_var.get(), '')
            self.assertEqual(sent['SSID'], 'First')
            self.assertEqual(sent['Keys'], 'test-password')
            # The core discards its mutable payload and snapshot after writing.
            self.assertEqual(self.dialog._settings._config, {})
            self.assertEqual(str(self.dialog.apply_button['state']), 'disabled')
            self.assertIn('acknowledged', self.dialog.status_var.get())


if __name__ == '__main__':
    unittest.main()
