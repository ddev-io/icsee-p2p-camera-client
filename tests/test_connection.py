import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from xmplayer.config.loader import load_monitor_config, validate_connection_credentials
from xmplayer.config.connection import save_connection_settings, read_account_credentials
from xmplayer.core import service
from xmplayer.core.cloud_id import ServiceCodes, DeviceStatus


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.login = self.root / 'login.txt'
        self.login.write_text('test-account\naccount-password\n', encoding='utf8')
        self.path = self.root / 'desktop_monitor.json'
        self.raw = {'device_id': 'OLDACCOUNT12345678', 'cloud_login_file': str(self.login),
                    'paths': {'screenshots_dir': str(self.root / 'screens')}}
        self.path.write_text(json.dumps(self.raw), encoding='utf8')
        self.config = load_monitor_config(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def cloud_config(self, password='camera-password'):
        path = save_connection_settings(self.config, mode='cloud_id', cloud_id='CAMERA123456789012345',
                                        device_username='camera-user', device_password=password)
        return load_monitor_config(path)

    def test_existing_config_defaults_to_account(self):
        self.assertEqual(self.config.connection_mode, 'account')
        self.assertIsNone(validate_connection_credentials(self.config))

    def test_cloud_id_is_saved_locally_and_does_not_change_the_account_file(self):
        original = self.path.read_text()
        config = self.cloud_config(' password with spaces ')
        self.assertEqual(config.device_id, 'CAMERA123456789012345')
        self.assertEqual(config.device_password, ' password with spaces ')
        self.assertEqual(self.path.read_text(), original)
        self.assertEqual(read_account_credentials(self.login), ('test-account', 'account-password'))
        self.assertNotIn(config.device_password, repr(config))

    def test_cloud_id_allows_empty_password_and_missing_account_file(self):
        config = self.cloud_config('')
        self.login.unlink()
        self.assertIsNone(validate_connection_credentials(config))
        self.assertEqual(service._connection_login_text(config), '')
        self.assertEqual(service.discover_cloud_device_ids(config), [config.device_id])

    def test_switching_back_to_account_clears_cloud_id_as_selected_camera(self):
        config = self.cloud_config()
        path = save_connection_settings(config, mode='account', account='new-account', account_password='new-pass')
        account = load_monitor_config(path)
        self.assertEqual(account.connection_mode, 'account')
        self.assertEqual(account.device_id, '')
        self.assertEqual(account.cloud_id, config.device_id)
        self.assertEqual(read_account_credentials(self.login), ('new-account', 'new-pass'))

    def test_unchanged_account_keeps_its_camera(self):
        path = save_connection_settings(self.config, mode='account', account='test-account',
                                        account_password='account-password')
        self.assertEqual(load_monitor_config(path).device_id, self.config.device_id)

    def test_invalid_cloud_id_does_not_save(self):
        with self.assertRaises(ValueError):
            save_connection_settings(self.config, mode='cloud_id', cloud_id='bad&id', device_username='admin')
        self.assertFalse((self.root / 'desktop_monitor.local.json').exists())

    def test_account_placeholders_are_not_prefilled(self):
        self.login.write_text('your_login\nyour_password\n')
        self.assertEqual(read_account_credentials(self.login), ('', ''))

    def test_cloud_refresh_uses_no_account_tokens_and_carries_the_verified_route(self):
        config = self.cloud_config()
        codes = ServiceCodes(config.device_id, {'rps': 'fresh-rps'})
        status = DeviceStatus('Online', 'rps', 'MSG_STATUS_MULTIQUERY_RSP',
                              {'ServerIP': '198.51.100.1', 'ServerPort': '6510'})
        with patch('xmplayer.core.cloud_id.CloudIdClient') as factory, patch.object(
                service, '_load_token_cache', side_effect=AssertionError('must not use account cache')), patch.object(
                service.legacy_cli, '_refresh_authcode_for_rps', side_effect=AssertionError('must not use account')):
            factory.return_value.auth_codes.return_value = codes
            factory.return_value.discover_status.return_value = status
            auth, info, token, admin_info = service._load_or_refresh_rps_tokens(
                config, raw_text='', serial_number=config.device_id, refresh_timeout=10,
                runtime_mode=config.runtime_mode, status_callback=None)
        self.assertEqual(auth, 'fresh-rps')
        self.assertEqual(token, '')
        self.assertEqual(admin_info['mode'], 'password')
        chain = service._make_rps_chain(config, info)
        self.assertEqual(chain.preferred_status_server, ('198.51.100.1', '6510'))
        login = service._build_login_followup(config.device_id, token, config.controller_profile, config=config)
        self.assertEqual(login['mode'], 'password')
        self.assertEqual(login['username'], 'camera-user')
        self.assertEqual(login['password'], 'camera-password')
        self.assertNotIn('admin_token', login)

    def test_account_login_builder_is_preserved(self):
        login = service._build_login_followup(self.config.device_id, 'account-device-token',
                                               self.config.controller_profile, config=self.config)
        self.assertEqual(login['mode'], 'auto')
        self.assertEqual(login['admin_token'], 'account-device-token')

    def test_cloud_messages_do_not_fall_back_to_a_saved_account(self):
        with self.assertRaisesRegex(service.MonitorCaptureError, 'account sign-in'):
            service.fetch_monitor_messages(self.cloud_config())

    def test_rejected_device_password_stops_monitor_retries(self):
        result = {'tcp_encrypted_probe': {'frames': {'control_frames': [
            {'cmd': 0x03E9, 'dataenc_decrypted_json': {'Ret': 203}}]}}}
        with self.assertRaisesRegex(service.MonitorCaptureError, 'rejected sign-in'):
            service._check_device_login(self.cloud_config(), result)
        service._check_device_login(self.config, result)


if __name__ == '__main__':
    unittest.main()
