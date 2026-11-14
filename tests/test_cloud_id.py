"""Account-free discovery: wire format, response correlation and safe output."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from xmplayer.core import legacy_api as api
from xmplayer.core.cloud_id import CloudIdClient, CloudIdError, ServiceCodes, DeviceStatus
from xmplayer.core.legacy_cli import main


SN = 'CAMERA123456789012345'
OTHER_SN = 'ANOTHER12345678901234'
AUTH = 'private-service-auth-code'
TIME = '00000021794320000000'


class CloudIdTests(unittest.TestCase):
    def setUp(self):
        self.client = CloudIdClient()
        self.codes = ServiceCodes(SN, {'rps': AUTH, 'dss': AUTH})

    def auth_response(self, payload):
        key = api._derive_ams_response_key(TIME, self.client.identity.secret)
        return api.HttpResult(True, 'private-url', 200, None,
                              api._encrypt_ams_hex_payload(json.dumps(payload), key))

    def status_response(self, *, sn=SN, status='Offline', code='200',
                        message='MSG_STATUS_LOCALQUERY_RSP', sequence='1'):
        body = {'StatusProtocol': {
            'Header': {'Version': '1.0', 'CSeq': sequence,
                       'MessageType': message, 'ErrorNum': code},
            'Body': [{'SerialNumber': sn, 'Status': status}],
        }}
        return api.HttpResult(True, 'private-url', 200, body, json.dumps(body))

    @patch.object(api, '_next_ams_time_millis', return_value=TIME)
    def test_native_auth_request_is_encrypted_and_has_no_account_credentials(self, _):
        result = self.auth_response({'code': 2000, 'data': [{'uuid': SN, 'rps': AUTH}]})
        with patch.object(api, 'http_text', return_value=result) as request:
            codes = self.client.auth_codes(SN)
        sent = request.call_args.kwargs
        self.assertTrue(sent['url'].startswith(f'https://rs.xmeye.net/acquery/v3/{TIME}/'))
        self.assertTrue(sent['url'].endswith('.rs'))
        key = api._derive_ams_response_key(TIME, self.client.identity.secret)
        self.assertEqual(api._decrypt_ams_hex_payload(sent['payload'], key), f'uuids={SN}')
        self.assertFalse(any(k.lower() in ('authorization', 'cookie') for k in sent['headers']))
        self.assertEqual(codes.for_service('rps'), AUTH)
        self.assertNotIn(SN, repr(codes))
        self.assertNotIn(AUTH, repr(codes))

    @patch.object(api, '_next_ams_time_millis', return_value=TIME)
    def test_auth_refreshes_on_each_call_and_selects_exact_device(self, _):
        result = self.auth_response({'code': 2000, 'data': [
            {'uuid': OTHER_SN, 'rps': 'foreign-code'}, {'uuid': SN, 'rps': AUTH}]})
        with patch.object(api, 'http_text', return_value=result) as request:
            self.assertEqual(self.client.auth_codes(SN).for_service('rps'), AUTH)
            self.client.auth_codes(SN)
        self.assertEqual(request.call_count, 2)

    @patch.object(api, '_next_ams_time_millis', return_value=TIME)
    def test_server_auth_rejection_does_not_disclose_message(self, _):
        result = self.auth_response({'code': 4000, 'msg': f'{SN} {AUTH}', 'data': []})
        with patch.object(api, 'http_text', return_value=result):
            with self.assertRaises(CloudIdError) as ctx:
                self.client.auth_codes(SN)
        self.assertEqual(ctx.exception.reason, 'server_rejected')
        self.assertEqual(ctx.exception.code, '4000')
        self.assertNotIn(SN, str(ctx.exception))
        self.assertNotIn(AUTH, str(ctx.exception))

    @patch.object(api, '_next_ams_time_millis', return_value=TIME)
    def test_foreign_or_duplicate_auth_rows_are_rejected(self, _):
        for rows in ([{'uuid': OTHER_SN, 'rps': AUTH}],
                     [{'uuid': SN, 'rps': AUTH}, {'uuid': SN, 'rps': AUTH}]):
            with self.subTest(rows=len(rows)), patch.object(
                    api, 'http_text', return_value=self.auth_response({'code': 2000, 'data': rows})):
                with self.assertRaisesRegex(CloudIdError, 'device_not_matched'):
                    self.client.auth_codes(SN)

    def test_malformed_encrypted_auth_response_is_rejected(self):
        result = api.HttpResult(True, 'private-url', 200, None, 'not-hex')
        with patch.object(api, 'http_text', return_value=result):
            with self.assertRaisesRegex(CloudIdError, 'invalid_encrypted_response'):
                self.client.auth_codes(SN)

    def test_valid_offline_is_a_device_status_not_a_transport_failure(self):
        with patch.object(api, 'status_protocol_query', return_value=self.status_response()):
            status = self.client.device_status(self.codes)
        self.assertEqual(status.status, 'Offline')
        self.assertNotIn(SN, repr(status))
        self.assertNotIn(SN, json.dumps(status.safe_summary()))

    def test_online_fixture_is_parsed_without_claiming_device_login(self):
        # Synthetic fixture; physical Online behavior has not yet been observed.
        with patch.object(api, 'status_protocol_query', return_value=self.status_response(status='Online')):
            status = self.client.device_status(self.codes)
        self.assertEqual(status.status, 'Online')
        self.assertNotIn('authenticated', status.safe_summary())

    def test_network_error_is_never_reported_as_offline(self):
        result = api.HttpResult(False, 'private-url', None, None, '', f'timeout {SN} {AUTH}')
        with patch.object(api, 'status_protocol_query', return_value=result):
            with self.assertRaisesRegex(CloudIdError, 'transport_error') as ctx:
                self.client.device_status(self.codes)
        self.assertNotIn(SN, str(ctx.exception))

    def test_http_success_does_not_override_protocol_rejection(self):
        with patch.object(api, 'status_protocol_query', return_value=self.status_response(code='400')):
            with self.assertRaisesRegex(CloudIdError, 'server_rejected'):
                self.client.device_status(self.codes)

    def test_certificate_failure_has_a_safe_specific_error(self):
        result = api.HttpResult(False, 'private-url', None, None, '',
                                f'[SSL: CERTIFICATE_VERIFY_FAILED] {SN}')
        with patch.object(api, 'status_protocol_query', return_value=result):
            with self.assertRaisesRegex(CloudIdError, 'tls_verification_failed') as ctx:
                self.client.device_status(self.codes)
        self.assertNotIn(SN, str(ctx.exception))

    def test_wrong_serial_sequence_message_and_unknown_status_are_rejected(self):
        for overrides, reason in [({'sn': OTHER_SN}, 'device_not_matched'),
                                  ({'sequence': '2'}, 'sequence_mismatch'),
                                  ({'message': 'WRONG_RSP'}, 'unexpected_message_type'),
                                  ({'status': 'Unexpected'}, 'unknown_device_status')]:
            with self.subTest(reason=reason), patch.object(
                    api, 'status_protocol_query', return_value=self.status_response(**overrides)):
                with self.assertRaisesRegex(CloudIdError, reason):
                    self.client.device_status(self.codes)

    def test_multi_uses_the_expected_command_and_selected_service_code(self):
        response = self.status_response(message='MSG_STATUS_MULTIQUERY_RSP')
        with patch.object(api, 'status_protocol_query', return_value=response) as request:
            self.client.device_status(self.codes, service='dss', multi=True)
        self.assertEqual(request.call_args.kwargs['message_type'], 'MSG_STATUS_MULTIQUERY_REQ')
        self.assertEqual(request.call_args.kwargs['authcode'], AUTH)

    def test_discovery_falls_back_to_multi_when_local_reports_offline(self):
        responses = [self.status_response(),
                     self.status_response(status='Online', message='MSG_STATUS_MULTIQUERY_RSP')]
        with patch.object(api, 'status_protocol_query', side_effect=responses) as request:
            status = self.client.discover_status(self.codes)
        self.assertEqual(status.status, 'Online')
        self.assertEqual(request.call_count, 2)

    def test_discovery_accepts_local_online_without_another_query(self):
        with patch.object(api, 'status_protocol_query', return_value=self.status_response(status='Online')) as request:
            self.assertEqual(self.client.discover_status(self.codes).status, 'Online')
        self.assertEqual(request.call_count, 1)

    def test_discovery_does_not_report_offline_if_multi_fails(self):
        timeout = api.HttpResult(False, '', None, None, '', 'timeout')
        with patch.object(api, 'status_protocol_query', side_effect=[self.status_response(), timeout]):
            with self.assertRaisesRegex(CloudIdError, 'transport_error'):
                self.client.discover_status(self.codes)

    def test_invalid_id_and_missing_service_never_send_a_request(self):
        with patch.object(api, 'http_text') as request:
            with self.assertRaisesRegex(CloudIdError, 'invalid_cloud_id'):
                self.client.auth_codes('bad&id=value')
            request.assert_not_called()
        with patch.object(api, 'status_protocol_query') as request:
            with self.assertRaisesRegex(CloudIdError, 'missing_service_code'):
                self.client.device_status(ServiceCodes(SN, {}))
            request.assert_not_called()

    @patch.object(api, '_next_ams_time_millis', return_value=TIME)
    def test_cli_reports_status_without_using_cloud_login_or_exposing_credentials(self, _):
        result = self.auth_response({'code': 2000, 'data': [{'uuid': SN, 'rps': AUTH}]})
        output = io.StringIO()
        with patch.object(api, 'http_text', return_value=result), patch.object(
                api, 'status_protocol_query', side_effect=[self.status_response(), self.status_response(
                    message='MSG_STATUS_MULTIQUERY_RSP')]), patch(
                'xmplayer.core.legacy_cli._login_cloud_session_for_rps',
                side_effect=AssertionError('must not use account login')), contextlib.redirect_stdout(output):
            exit_code = main(['cloud-id-status', '--device-id', SN])
        text = output.getvalue()
        metadata = json.loads(text)
        self.assertEqual(exit_code, 0)
        self.assertEqual(metadata['device_status'], 'Offline')
        self.assertFalse(metadata['account_login_used'])
        self.assertEqual(metadata['device_authentication'], 'not_attempted')
        self.assertNotIn(SN, text)
        self.assertNotIn(AUTH, text)


class CloudIdLoginProbeTests(unittest.TestCase):
    def setUp(self):
        self.client = CloudIdClient()
        self.codes = ServiceCodes(SN, {'rps': AUTH})
        self.status = DeviceStatus('Online', 'rps', 'MSG_STATUS_MULTIQUERY_RSP',
                                   {'ServerIP': '198.51.100.1', 'ServerPort': '6510',
                                    'DevicePort': '34567'})
        self.selector = api.HttpResult(True, '', 200, {'AgentProtocol': {
            'Header': {'ErrorNum': '200'}, 'Body': {
                'AgentServerIp': '198.51.100.2', 'AgentServerPort': '6611'}}}, '')

    def transport_result(self, ret=100, reply_id=24, sent=True, handshake=True):
        return {'status': 'ok', 'handshake': {'ok': handshake},
                'claim': {'followups': [{'cmd': 1000, 'msg_id': 24}] if sent else []},
                'frames': {'control_frames': [{'cmd': 1001, 'msg_id': reply_id,
                                               'payload_text': json.dumps({'Ret': ret})}]}}

    def run_probe(self, transport_result):
        with patch.object(self.client, 'auth_codes', return_value=self.codes), patch.object(
                self.client, 'discover_status', return_value=self.status), patch.object(
                api, 'agent_protocol_query', return_value=self.selector), patch.object(
                api, 'get_agent_client_uuid', return_value='test-client'), patch.object(
                api.AgentTcpEncryptedClaimProbe, 'run_probe', return_value=transport_result) as probe:
            result = self.client.probe_login(SN, username='camera-user', password='camera-password')
        return result, probe

    def test_login_requires_correlated_device_ack_and_passes_password_mode(self):
        result, probe = self.run_probe(self.transport_result())
        self.assertTrue(result['authenticated'])
        self.assertEqual(result['device_authentication'], 'success')
        self.assertFalse(result['account_login_used'])
        sent = probe.call_args.kwargs
        self.assertEqual(sent['xor_key'], '')
        self.assertEqual(sent['login_followup_builder']['mode'], 'password')
        self.assertEqual(sent['login_followup_builder']['random_a'], sent['claim_random_a'])
        self.assertEqual(sent['login_followup_builder']['password'], 'camera-password')
        self.assertFalse(sent['controller_auto'])
        text = json.dumps(result)
        for value in (SN, AUTH, 'camera-user', 'camera-password', 'test-client'):
            self.assertNotIn(value, text)

    def test_credential_rejection_is_reported_without_retry(self):
        result, probe = self.run_probe(self.transport_result(ret=203))
        self.assertFalse(result['authenticated'])
        self.assertEqual(result['reason'], 'incorrect_password')
        self.assertEqual(probe.call_count, 1)

    def test_locked_user_is_reported_without_retry(self):
        result, probe = self.run_probe(self.transport_result(ret=205))
        self.assertFalse(result['authenticated'])
        self.assertEqual(result['reason'], 'user_locked')
        self.assertEqual(probe.call_count, 1)

    def test_generic_transport_ok_and_unmatched_replies_are_not_login_success(self):
        for change in ({'reply_id': 99}, {'sent': False}, {'handshake': False}, {'ret': None}):
            with self.subTest(change=change):
                result, _ = self.run_probe(self.transport_result(**change))
                self.assertFalse(result['authenticated'])

    def test_offline_does_not_send_credentials_to_a_relay(self):
        offline = DeviceStatus('Offline', 'rps', 'MSG_STATUS_MULTIQUERY_RSP', {})
        with patch.object(self.client, 'auth_codes', return_value=self.codes), patch.object(
                self.client, 'discover_status', return_value=offline), patch.object(
                api, 'agent_protocol_query') as request:
            result = self.client.probe_login(SN, username='camera-user', password='camera-password')
        self.assertEqual(result['reason'], 'device_offline')
        self.assertEqual(result['device_authentication'], 'not_attempted')
        request.assert_not_called()

    def test_bad_route_is_rejected_before_connecting(self):
        self.status.entry['ServerPort'] = 'invalid'
        with self.assertRaisesRegex(CloudIdError, 'invalid_relay_address'):
            self.run_probe(self.transport_result())

    def test_selector_protocol_error_is_not_overridden_by_http_200(self):
        self.selector.json_data['AgentProtocol']['Header']['ErrorNum'] = '400'
        with self.assertRaisesRegex(CloudIdError, 'server_rejected'):
            self.run_probe(self.transport_result())


if __name__ == '__main__':
    unittest.main()
