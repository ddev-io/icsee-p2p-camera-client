import copy
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from xmplayer.core import wifi


def response(name, cmd, body=None, ret=100):
    data = {'Name': name, 'Ret': ret, 'SessionID': '0x00000001'}
    if body is not None:
        data[name] = body
    return {'tcp_encrypted_probe': {'frames': {'control_frames': [
        {'cmd': cmd + 1, 'dataenc_decrypted_json': data},
    ]}}}


class WifiTests(unittest.TestCase):
    def setUp(self):
        self.current = {'SSID': 'Old', 'Keys': 'old-secret', 'Auth': 'WPA2', 'EncrypType': 'AES',
                        'KeyType': 1, 'Enable': True, 'HostIP': '0x01020304',
                        'Submask': '0x00FFFFFF', 'GateWay': '0x01020301',
                        'FirmwareExtra': {'Keep': True}}
        self.network = wifi.WifiNetwork('New % + сеть', 'WPA2PSK', 'AES', 6, '-55')

    def test_scan_decodes_utf8_without_url_decoding_ssid(self):
        encoded = ''.join('\\x%02x' % b for b in 'сеть'.encode())
        name = f'100% + {encoded} '
        rows = [{'SSID': name, 'Auth': 'WPA2PSK', 'EncrypType': 'AES', 'Channel': 6, 'nRSSI': -55},
                {'SSID': name, 'Auth': 'WPA2PSK', 'EncrypType': 'AES'}, {'SSID': ''}]
        networks = wifi.parse_wifi_networks({'WifiAP': {'Numbers': 3, 'WifiAP': rows}})
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0].ssid, '100% + сеть ')
        self.assertEqual(networks[0].signal, '-55')

    def test_empty_scan_is_not_malformed_scan(self):
        self.assertEqual(wifi.parse_wifi_networks({'WifiAP': {'Numbers': 0}}), [])
        with self.assertRaises(wifi.service.MonitorCaptureError):
            wifi.parse_wifi_networks({'WifiAP': {'Numbers': 2}})

    def test_save_preserves_unknown_and_ip_fields_and_spaces(self):
        original = copy.deepcopy(self.current)
        body = wifi.build_wifi_config(self.current, ' Network ', ' password ')
        self.assertEqual(body['SSID'], ' Network ')
        self.assertEqual(body['Keys'], ' password ')
        for key in ('HostIP', 'Submask', 'GateWay', 'FirmwareExtra'):
            self.assertEqual(body[key], original[key])
        body['FirmwareExtra']['Keep'] = False
        self.assertEqual(self.current, original)
        self.assertEqual((body['Auth'], body['EncrypType'], body['KeyType']), ('WPA2', 'AES', 1))

    def test_open_network_clears_password(self):
        body = wifi.build_wifi_config(self.current, 'Open', '')
        self.assertEqual((body['Auth'], body['EncrypType'], body['Keys']), ('OPEN', 'NONE', ''))

    def test_ssid_limit_is_utf8_bytes_not_characters(self):
        with self.assertRaises(ValueError):
            wifi.build_wifi_config(self.current, 'я' * 17, 'password')
        self.assertEqual(wifi.build_wifi_config(self.current, 'я' * 16, 'password')['SSID'], 'я' * 16)

    def test_invalid_input_is_rejected(self):
        for ssid, password in (('', 'password'), ('x\x00y', 'password'), ('Network', 'short'),
                               ('Network', 'p\x00assword'), ('Network', 'z' * 64)):
            with self.subTest(ssid=ssid, password=password), self.assertRaises(ValueError):
                wifi.build_wifi_config(self.current, ssid, password)
        self.assertEqual(wifi.build_wifi_config(self.current, 'Network', 'a' * 64)['Keys'], 'a' * 64)

    def test_only_network_from_camera_scan_can_be_saved(self):
        settings = wifi.CameraWifi('Old', [self.network], _config=self.current)
        with patch.object(wifi, '_command') as command:
            with self.assertRaises(ValueError):
                wifi.save_camera_wifi(None, settings, wifi.WifiNetwork('Typed manually', 'WPA2PSK', 'AES'), 'password')
            command.assert_not_called()

    def test_unsupported_security_cannot_be_saved(self):
        network = wifi.WifiNetwork('WEP', 'SHARED', 'WEP')
        settings = wifi.CameraWifi('Old', [network], _config=self.current)
        with patch.object(wifi, '_command') as command:
            with self.assertRaises(ValueError):
                wifi.save_camera_wifi(None, settings, network, 'password')
            command.assert_not_called()

    def test_write_discards_snapshot_even_without_acknowledgement(self):
        settings = wifi.CameraWifi('Old', [self.network], _config=self.current)
        with patch.object(wifi, '_command', side_effect=wifi.WifiSaveUnconfirmed('unconfirmed')):
            with self.assertRaises(wifi.WifiSaveUnconfirmed):
                wifi.save_camera_wifi(None, settings, self.network, 'password')
        self.assertEqual(settings._config, {})
        self.assertNotIn('old-secret', repr(settings))

    def test_response_must_match_both_name_and_command(self):
        result = response('Other', wifi.GET_CONFIG, self.current)
        self.assertIsNone(wifi._find_response(result, wifi.WIFI_CONFIG, wifi.GET_CONFIG))
        result = response(wifi.WIFI_CONFIG, wifi.GET_CONFIG, self.current)
        self.assertIsNone(wifi._find_response(result, wifi.WIFI_CONFIG, wifi.SET_CONFIG))
        self.assertEqual(wifi._find_response(result, wifi.WIFI_CONFIG, wifi.GET_CONFIG)['Ret'], 100)

    def _config(self, root):
        login = root / 'login.txt'
        login.write_text('test-user\ntest-password\n')
        return SimpleNamespace(cloud_login_file=login, device_id='test-camera', runtime_mode='experimental_current',
                               controller_profile='app_reference_first_6611')

    def test_transport_builds_encrypted_scan_request_with_runtime_session(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(Path(directory))
            with patch.object(wifi.service, '_load_or_refresh_rps_tokens', return_value=('auth', {}, 'admin', {})), \
                 patch.object(wifi.service, '_cached_status_servers', return_value=[]), \
                 patch.object(wifi.service, '_agent_client_token', return_value='client'), \
                 patch.object(wifi.legacy_api, 'RpsLiveChain') as factory:
                factory.return_value.run.return_value = response(wifi.WIFI_SCAN, wifi.SCAN_WIFI, {'Numbers': 0})
                result = wifi._command(config, wifi.WIFI_SCAN, wifi.SCAN_WIFI)
                self.assertEqual(result['Ret'], 100)
                kwargs = factory.return_value.run.call_args.kwargs
                frame = kwargs['encrypted_followup_frames'][0]
                self.assertEqual(frame['cmd'], 1020)
                self.assertEqual(json.loads(frame['plain_payload_text']), {'Name': 'WifiAP', 'SessionID': '{{SESSION_ID}}'})
                self.assertFalse(kwargs['encrypted_controller_auto'])
                self.assertFalse(kwargs['plain_handoff'])

    def test_missing_write_acknowledgement_does_not_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(Path(directory))
            with patch.object(wifi.service, '_load_or_refresh_rps_tokens', return_value=('auth', {}, 'admin', {})), \
                 patch.object(wifi.service, '_cached_status_servers', return_value=[('relay-one', '6611'), ('relay-two', '6611')]), \
                 patch.object(wifi.service, '_agent_client_token', return_value='client'), \
                 patch.object(wifi.legacy_api, 'RpsLiveChain') as factory:
                factory.return_value.run.return_value = {'status': 'error'}
                with self.assertRaises(wifi.WifiSaveUnconfirmed) as caught:
                    wifi._command(config, wifi.WIFI_CONFIG, wifi.SET_CONFIG, body=self.current)
                self.assertNotIn('old-secret', str(caught.exception))
                self.assertEqual(factory.return_value.run.call_count, 1)

    def test_cancellation_prevents_any_request(self):
        stopped = threading.Event()
        stopped.set()
        with patch.object(wifi.legacy_api, 'RpsLiveChain') as factory:
            with self.assertRaises(wifi.service.MonitorCancelled):
                wifi._command(None, wifi.WIFI_SCAN, wifi.SCAN_WIFI, stop_event=stopped)
            factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
