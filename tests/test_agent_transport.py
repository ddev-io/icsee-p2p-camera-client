import base64
import json
import socket
import time
import unittest
from unittest.mock import patch

from xmplayer.core import legacy_api as api
from xmplayer.core import legacy_cli, service


class FakeAgentRelay:
    """In-memory relay and camera: handshake, claim, login, config query."""
    def __init__(self, key='', ack_code='200', claim_aes=True):
        self.key = key
        self.ack_code = ack_code
        self.claim_aes = claim_aes
        self.rx = api._XorKeystream(key) if key else None
        self.tx = api._XorKeystream(key) if key else None
        self.incoming = []
        self.handshake_wire = None
        self.frames = []
        self.wire_frames = []
        self.closed = False

    def settimeout(self, timeout):
        pass

    def close(self):
        self.closed = True

    def recv(self, size):
        if self.incoming:
            data = self.incoming.pop(0)
            if len(data) > size:
                self.incoming.insert(0, data[size:])
            return data[:size]
        time.sleep(0.001)
        raise socket.timeout()

    def sendall(self, wire):
        if self.handshake_wire is None:
            if not wire.endswith(b'XXEE'):
                raise AssertionError('relay requires a literal XXEE terminator')
            fields = base64.b64decode(wire[:-4], validate=True).decode().split(':')
            if len(fields) != 4:
                raise AssertionError('expected four handshake fields')
            self.handshake_wire = wire
            ack = base64.b64encode(json.dumps({'ErrorNum': self.ack_code}).encode()) + b'XXEE'
            self.incoming.extend([ack[:-2], ack[-2:]])
            return
        self.wire_frames.append(wire)
        clear = self.rx.apply(wire) if self.rx else wire
        frames, remainder = api._parse_tcp_frames(clear)
        if remainder or not frames:
            raise AssertionError('invalid control frame or wrong stream cipher')
        for frame in frames:
            self.frames.append(frame)
            if frame.cmd == 0x0585:
                body = json.dumps({'Ret': 100, 'SessionID': '0x77', 'NotEncryptMsgID': []}).encode()
                if self.claim_aes:
                    body += b'\0' * (-len(body) % 16)
                    body = base64.b64encode(api._AES.new(api.SPECIAL_LOGIN_AES_KEY, api._AES.MODE_CBC,
                                                        iv=b'\0' * 16).encrypt(body))
                self.reply(0x0586, body, session=1099999 if self.claim_aes else 0x77)
            elif frame.cmd == 0x03E8:
                self.reply(0x03E9, json.dumps({'Ret': 100, 'SessionID': '0x77'}).encode())
            elif frame.cmd == 0x0412:
                self.reply(0x0413, json.dumps({'Ret': 100, 'Name': 'NetWork.Wifi',
                                             'NetWork.Wifi': {'SSID': 'Test network'}}).encode())

    def reply(self, cmd, payload, session=0x77):
        frame = api._build_tcp_frame(msg_type=0, session_id=session, msg_id=56,
                                     code=0, cmd=cmd, payload=payload + b'\0')
        self.incoming.append(self.tx.apply(frame) if self.tx else frame)


def login_candidate(**kwargs):
    return {'status': 'ok', 'mode': 'test-token-login',
            'frame': {'cmd': 0x03E8, 'session_id': 0x77, 'msg_id': 56},
            'transport': {'payload_text': '{"Name":"Login","SessionID":"0x77"}'}}


def query_template():
    return {'cmd': 0x0412, 'msg_id': 72, 'send_phase': 'post_login',
            'plain_payload_text': '{"Name":"NetWork.Wifi","SessionID":"{{SESSION_ID}}"}',
            'stop_after_response_cmd': 0x0413}


class AgentTransportTests(unittest.TestCase):
    def probe(self, relay):
        with patch.object(api, '_create_tcp_connection', return_value=relay), \
             patch.object(api, 'build_6611_login_candidate', side_effect=login_candidate) as builder:
            result = api.AgentTcpEncryptedClaimProbe().run_probe(
                host='relay.test', port=6611, authcode='test-auth', client_token='test-client',
                serial='test-camera', session='test-session', xor_key=relay.key, claim_random_a='test-random-a',
                session_int=99999, channel=0, stream_type='Main', trans_mode='TCP', combine_mode='CONNECT_ALL',
                msg_id=48, unk=99, cmd=0x0585, timeout=0.2, capture_seconds=0.5, max_frames=8,
                login_followup_builder={'admin_token': 'test-admin-token'}, followup_frames=[query_template()],
            )
            return result, builder

    def test_no_randomstr_keeps_claim_token_login_and_post_login_query(self):
        relay = FakeAgentRelay()
        result, builder = self.probe(relay)
        self.assertTrue(result['handshake']['ok'])
        self.assertEqual(result['stream_encoding'], 'none')
        self.assertEqual([frame.cmd for frame in relay.frames], [0x0585, 0x03E8, 0x0412])
        self.assertEqual(builder.call_args.kwargs['admin_token'], 'test-admin-token')
        self.assertEqual(relay.frames[-1].session_id, 0x77)
        self.assertIn(b'"SessionID":"0x77"', relay.frames[-1].payload)
        self.assertEqual(result['frames']['control'], 3)
        self.assertTrue(relay.closed)

    def test_randomstr_keeps_xor_in_both_directions(self):
        relay = FakeAgentRelay('ABCDEFGH')
        result, _ = self.probe(relay)
        self.assertEqual(result['stream_encoding'], 'xor')
        self.assertFalse(relay.wire_frames[0].startswith(api.TCP_MAGIC))
        self.assertEqual([frame.cmd for frame in relay.frames], [0x0585, 0x03E8, 0x0412])
        self.assertEqual(result['frames']['control'], 3)

    def test_plain_claim_json_can_still_build_camera_login(self):
        relay = FakeAgentRelay(claim_aes=False)
        result, builder = self.probe(relay)
        self.assertTrue(result['handshake']['ok'])
        builder.assert_called_once()
        self.assertEqual([frame.cmd for frame in relay.frames], [0x0585, 0x03E8, 0x0412])

    def test_relay_rejection_stops_before_camera_commands(self):
        relay = FakeAgentRelay(ack_code='403')
        result, builder = self.probe(relay)
        self.assertFalse(result['handshake']['ok'])
        self.assertIn('ErrorNum=403', result['error'])
        self.assertEqual(relay.frames, [])
        builder.assert_not_called()

    def test_chain_routes_missing_randomstr_through_full_control_engine(self):
        relay = FakeAgentRelay()
        response = {'AgentProtocol': {'Header': {'ErrorNum': '200'}, 'Body': {
            'AgentServerIp': 'relay.test', 'AgentServerPort': 6611, 'ProtocolMode': 'tcp'}}}
        with patch.object(api, '_create_tcp_connection', return_value=relay), \
             patch.object(api, 'build_6611_login_candidate', side_effect=login_candidate), \
             patch.object(api, 'agent_protocol_query', return_value=api.HttpResult(True, 'test', 200, response, '')), \
             patch.object(api.AgentTcpLiveProbe, 'run_probe', side_effect=AssertionError('legacy plain probe loses login')):
            result = api.RpsLiveChain().run(
                serial_number='test-camera', authcode='test-auth', client_token='test-client', session_id='test-session',
                status_server_ip='status.test', status_server_port='6510', dest_port='34567', service_type='RpsCmd',
                encrypt='1', step='0', protocol_mode='tcp', timeout=1, channel=0, stream_type='Main', trans_mode='TCP',
                combine_mode='NONE', msg_id=24, code=0x8505, code_endian='be', capture_seconds=0.5, max_frames=8,
                tcp_mode='encrypted', encrypted_login_followup={'admin_token': 'test-admin-token'},
                encrypted_followup_frames=[query_template()], wakeup_probe_enabled=False,
            )
        probe = result['tcp_encrypted_probe']
        self.assertEqual(probe['stream_encoding'], 'none')
        self.assertEqual(probe['frames']['control'], 3)
        self.assertEqual(service.describe_capture_failure(result), '')

    def test_all_base64_padding_alignments_use_external_terminator(self):
        for length in range(3):
            raw = f'auth:token:camera:session{"x" * length}'.encode()
            wire = api.AgentTcpLiveProbe().build_handshake('auth', 'token', 'camera', 'session' + 'x' * length)
            self.assertEqual(wire, base64.b64encode(raw) + b'XXEE')

    def test_cli_reference_parser_handles_actual_wire(self):
        wire = api.AgentTcpLiveProbe().build_handshake('a', 'b', 'c', 'd').decode()
        parsed = legacy_cli._split_handshake_text(wire)
        self.assertEqual(parsed['parts_count'], 4)
        self.assertEqual(parsed['session'], 'd')
        self.assertEqual(parsed['wire_terminator'], 'XXEE')


if __name__ == '__main__':
    unittest.main()
