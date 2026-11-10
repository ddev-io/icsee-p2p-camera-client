import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

from xmplayer.core import ams_regions, legacy_api, legacy_cli, service


EU, SA, NA, AS = ams_regions.AMS_BASES
CAMERA = 'test-camera-sa'


class AmsRegionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.login = self.root / 'login.txt'
        self.login.write_text('test-account\ntest-password\n')
        self.cache_path = self.root / 'ams_cache.json'
        self.cache = ams_regions.AmsCache('test-identity', self.cache_path)
        self.extractor = legacy_api.CloudLiveExtractor()
        self.extractor.ams_cache = self.cache
        self.session = legacy_api.CloudAuthSession(
            account='test-account', user_token='opaque-session-token', app_key=legacy_cli.DEFAULT_ICSEE_APP_KEY,
            uuid=legacy_cli.DEFAULT_ICSEE_UUID, move_card=2, secret=legacy_cli.DEFAULT_ICSEE_SECRET,
        )
        self.devices = {EU: [], SA: [{'uuid': CAMERA, 'rps': 'ams-rps-auth'}], NA: [], AS: []}
        self.auths = {SA: [{'uuid': CAMERA, 'type': 'rps', 'auth': 'acapp-rps-auth'}]}
        self.requests = []
        self.overrides = {}
        self.addCleanup(patch.stopall)
        patch.object(legacy_cli, 'AmsCache', side_effect=lambda identity: ams_regions.AmsCache(identity, self.cache_path)).start()
        patch.dict('os.environ', {'XMPLAYER_AMS_BASE': ''}).start()
        patch.object(legacy_api, 'http_text', side_effect=self.http).start()
        patch.object(legacy_api, 'http_json', side_effect=AssertionError('unexpected network request')).start()

    def http(self, *, url, **kwargs):
        parts = urlsplit(url)
        base = f'https://{parts.hostname}'
        endpoint = parts.path.split('/')[1]
        self.requests.append((base, endpoint, kwargs))
        override = self.overrides.get((base, endpoint))
        if override:
            status, text = override.pop(0)
            return legacy_api.HttpResult(status == 200, url, status, None, text)
        if endpoint == 'loginExist':
            data = {'data': {'accessToken': 'opaque-login-token'}}
        elif endpoint == 'msdlistCode':
            data = {'data': {'mine': [], 'share': self.devices.get(base, [])}}
        elif endpoint == 'acapp':
            data = {'data': self.auths.get(base, [])}
        else:
            raise AssertionError(endpoint)
        timestamp = parts.path.split('/')[-2]
        key = legacy_api._derive_ams_response_key(timestamp, legacy_cli.DEFAULT_ICSEE_SECRET)
        encrypted = legacy_api._encrypt_ams_hex_payload(json.dumps(data), key)
        return legacy_api.HttpResult(True, url, 200, None, encrypted)

    def fetch(self, serial=''):
        return self.extractor.fetch_ams_device_list(self.session, serial_number=serial)

    def test_empty_eu_falls_back_to_shared_camera_in_sa(self):
        session, devices, _ = self.fetch()
        self.assertEqual(devices[0]['_device_id'], CAMERA)
        self.assertEqual(session.ams_base, SA)
        self.assertEqual([base for base, _, _ in self.requests], [EU, SA])

    def test_other_camera_in_eu_does_not_stop_targeted_search(self):
        self.devices[EU] = [{'uuid': 'different-camera'}]
        _, devices, _ = self.fetch(CAMERA)
        self.assertEqual(devices[0]['_device_id'], CAMERA)
        self.assertEqual(self.cache.preferred_region(CAMERA), SA)

    def test_existing_eu_camera_still_uses_one_request(self):
        self.devices[EU] = [{'uuid': CAMERA}]
        self.fetch(CAMERA)
        self.assertEqual([base for base, _, _ in self.requests], [EU])

    def test_region_hint_survives_restart_and_is_per_camera(self):
        self.fetch(CAMERA)
        fresh = legacy_api.CloudLiveExtractor()
        fresh.ams_cache = ams_regions.AmsCache('test-identity', self.cache_path)
        self.requests.clear()
        fresh.fetch_ams_device_list(self.session, serial_number=CAMERA)
        self.assertEqual(self.requests[0][0], SA)
        self.cache.remember_region(EU, 'another-camera')
        self.assertEqual(self.cache.preferred_region(CAMERA), SA)

    def test_override_is_strict_and_does_not_fall_back(self):
        self.extractor.ams_base_override = 'eu'
        _, devices, _ = self.fetch(CAMERA)
        self.assertEqual(devices, [])
        self.assertEqual([base for base, _, _ in self.requests], [EU])

    def test_unreachable_region_continues_search(self):
        self.overrides[(EU, 'msdlistCode')] = [(503, 'unavailable')]
        _, devices, _ = self.fetch(CAMERA)
        self.assertEqual(devices[0]['_device_id'], CAMERA)

    def test_wrong_acapp_device_and_auth_type_continue_search(self):
        self.auths[EU] = [{'uuid': CAMERA, 'type': 'pms', 'auth': 'wrong-service'},
                          {'uuid': 'other', 'type': 'rps', 'auth': 'wrong-camera'}]
        _, rows, _ = self.extractor.fetch_acapp_auth_list(self.session, serial_number=CAMERA)
        self.assertEqual(rows[0]['_auth_code'], 'acapp-rps-auth')
        self.assertEqual([base for base, _, _ in self.requests], [EU, SA])

    def test_nonhex_reply_does_not_trigger_repeated_logins(self):
        self.overrides[(EU, 'msdlistCode')] = [(200, 'temporarily limited')]
        self.extractor._last_login_kwargs = {'mode': 'ams_password'}
        with patch.object(self.extractor, 'login_with_ams_credentials') as login:
            _, devices, _ = self.fetch(CAMERA)
            login.assert_not_called()
        self.assertEqual(devices[0]['_device_id'], CAMERA)

    def test_auth_rejection_refreshes_only_once_on_same_server(self):
        self.overrides[(EU, 'msdlistCode')] = [(401, 'unauthorized'), (401, 'unauthorized')]
        self.extractor.ams_base_override = 'eu'
        self.extractor._last_login_kwargs = {'mode': 'ams_password'}
        with patch.object(self.extractor, 'login_with_ams_credentials', return_value=(self.session, [])) as login:
            _, devices, _ = self.fetch(CAMERA)
            login.assert_called_once()
            self.assertEqual(login.call_args.kwargs['ams_bases'], [EU])
        self.assertEqual(devices, [])
        self.assertEqual(len(self.requests), 2)

    def test_cache_expires_without_losing_region_hint(self):
        with patch.object(ams_regions.time, 'time', return_value=1000):
            self.cache.remember_region(SA, CAMERA)
            self.cache.save_session(self.session, fresh=True)
        with patch.object(ams_regions.time, 'time', return_value=2000):
            self.assertIsNone(self.cache.load_session())
            self.assertEqual(self.cache.preferred_region(CAMERA), SA)

    def test_reading_devices_does_not_extend_session_lifetime(self):
        with patch.object(ams_regions.time, 'time', return_value=1000):
            self.cache.save_session(self.session, fresh=True)
        with patch.object(ams_regions.time, 'time', return_value=1500):
            self.cache.save_session(self.session)
        with patch.object(ams_regions.time, 'time', return_value=1910):
            self.assertIsNone(self.cache.load_session())

    def test_jwt_expiry_bounds_cache_lifetime(self):
        claims = base64.urlsafe_b64encode(json.dumps({'exp': 1100}).encode()).decode().rstrip('=')
        self.session.user_token = f'header.{claims}.signature'
        with patch.object(ams_regions.time, 'time', return_value=1000):
            self.cache.save_session(self.session, fresh=True)
        with patch.object(ams_regions.time, 'time', return_value=1080):
            self.assertIsNone(self.cache.load_session())

    def test_region_specific_token_is_refreshed_only_after_rejection(self):
        self.overrides[(SA, 'msdlistCode')] = [(401, 'unauthorized')]
        auth, info = legacy_cli._refresh_authcode_for_rps(
            text='', serial_number=CAMERA, timeout=1, login_file=str(self.login),
        )
        self.assertEqual(auth, 'acapp-rps-auth')
        self.assertEqual(info['ams_base'], SA)
        self.assertEqual([base for base, endpoint, _ in self.requests if endpoint == 'loginExist'], [EU, SA])

    def test_expired_session_relogs_into_last_working_region(self):
        legacy_cli._refresh_authcode_for_rps(text='', serial_number=CAMERA, timeout=1, login_file=str(self.login))
        saved = json.loads(self.cache_path.read_text())
        saved['expires_at'] = 1
        self.cache_path.write_text(json.dumps(saved))
        self.requests.clear()
        legacy_cli._refresh_authcode_for_rps(text='', serial_number=CAMERA, timeout=1, login_file=str(self.login))
        self.assertEqual([base for base, endpoint, _ in self.requests if endpoint == 'loginExist'], [SA])

    def test_readonly_cache_does_not_prevent_access(self):
        with patch.object(ams_regions.os, 'replace', side_effect=OSError('read-only')):
            self.cache.save_session(self.session, fresh=True)
        self.assertFalse(self.cache_path.exists())
        self.assertEqual(list(self.root.glob('ams_cache.json.*.tmp')), [])

    def test_identity_and_override_isolate_cached_credentials(self):
        first = ams_regions.credential_identity('account', 'password', 'app')
        self.assertNotEqual(first, ams_regions.credential_identity('another-account', 'password', 'app'))
        self.assertNotEqual(first, ams_regions.credential_identity('account', 'changed', 'app'))
        self.assertNotEqual(first, ams_regions.credential_identity('account', 'password', 'app', 'sa'))
        self.cache.save_session(self.session, fresh=True)
        self.assertIsNone(ams_regions.AmsCache('different', self.cache_path).load_session())

    def test_rejects_nonofficial_and_credential_bearing_urls(self):
        for value in ['http://sa-ams.jftechws.com', 'https://sa-ams.jftechws.com.evil.test',
                      'https://user:pass@sa-ams.jftechws.com', 'https://sa-ams.jftechws.com/path']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                ams_regions.normalize_ams_base(value)
        self.assertEqual(ams_regions.normalize_ams_base('sa'), SA)

    def test_token_refresh_reuses_login_and_binds_camera_cache_to_account(self):
        def jvss(_extractor, session, device_id, **kwargs):
            session.device_token = 'test-admin-token'
            return session, []
        config = SimpleNamespace(project_root=self.root, cloud_login_file=self.login, ams_base='')
        arguments = dict(raw_text='', serial_number=CAMERA, refresh_timeout=1,
                         runtime_mode='experimental_current', status_callback=None)
        with patch.object(legacy_api.CloudLiveExtractor, 'fetch_jvss_device_login_token', autospec=True, side_effect=jvss):
            auth, info, _, _ = service._load_or_refresh_rps_tokens(config, **arguments)
            self.assertEqual(auth, 'acapp-rps-auth')
            self.assertEqual(info['ams_base'], SA)
            self.assertEqual(sum(endpoint == 'loginExist' for _, endpoint, _ in self.requests), 1)
            count = len(self.requests)
            service._load_or_refresh_rps_tokens(config, **arguments)
            self.assertEqual(len(self.requests), count)
            self.login.write_text('another-account\nnew-test-password\n')
            self.assertIsNone(service._load_token_cache(config, serial_number=CAMERA, runtime_mode='experimental_current'))
        cache_text = self.cache_path.read_text()
        self.assertNotIn('test-password', cache_text)
        self.assertNotIn('test-account', cache_text)
        self.assertNotIn('raw_login', cache_text)


if __name__ == '__main__':
    unittest.main()
