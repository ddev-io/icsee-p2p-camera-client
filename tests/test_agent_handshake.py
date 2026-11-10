"""Offline regression tests for the SDK-style TCP/6611 handshake."""
import base64
import unittest

from xmplayer.core.legacy_api import (
    AgentTcpLiveProbe,
    AgentTcpEncryptedClaimProbe,
    TCP_HANDSHAKE_SUFFIX,
    WAKEUP_SUFFIX,
    _decode_base64_with_suffix,
    _recv_base64_message,
)


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
    def settimeout(self, timeout):
        pass
    def recv(self, n):
        return next(self.chunks, b'')


class AgentHandshakeTests(unittest.TestCase):
    def test_absent_randomstr_builds_sdk_wire_format(self):
        self.assertEqual(TCP_HANDSHAKE_SUFFIX, b'')
        payload = AgentTcpLiveProbe().build_handshake('auth', 'token', 'serial', 'session')
        self.assertEqual(payload, base64.b64encode(b'auth:token:serial:session') + b'XXEE')

    def test_encrypted_probe_uses_same_first_handshake(self):
        payload = AgentTcpEncryptedClaimProbe().build_handshake('a', 'b', 'c', 'd')
        self.assertEqual(payload, base64.b64encode(b'a:b:c:d') + b'XXEE')

    def test_optional_interior_suffix_is_encoded_before_xxee(self):
        payload = AgentTcpLiveProbe(b']q\x04').build_handshake('a', 'b', 'c', 'd')
        self.assertEqual(payload, base64.b64encode(b'a:b:c:d]q\x04') + b'XXEE')

    def test_ack_decodes_without_randomstr(self):
        wire = base64.b64encode(b'{"ErrorNum": "200"}') + b'XXEE'
        payload, remainder, err = _recv_base64_message(FakeSocket([wire]), 0.5, b'')
        self.assertFalse(err)
        self.assertFalse(remainder)
        decoded, err = _decode_base64_with_suffix(payload, b'')
        self.assertFalse(err)
        self.assertEqual(AgentTcpLiveProbe().parse_handshake_response(decoded)['json']['ErrorNum'], '200')

    def test_fragmented_xxee_is_consumed_with_handshake(self):
        wire = base64.b64encode(b'{"ErrorNum":"200"}') + b'XXEE'
        fragments = [wire[:-2], wire[-2:] + b'\xff\x01MORE']
        payload, remainder, err = _recv_base64_message(FakeSocket(fragments), 0.5, b'')
        self.assertFalse(err)
        self.assertEqual(payload, wire)
        self.assertEqual(remainder, b'\xff\x01MORE')

    def test_partial_response_does_not_count_as_handshake(self):
        wire = base64.b64encode(b'{"ErrorNum":"200"}')
        payload, remainder, err = _recv_base64_message(FakeSocket([wire]), 0.5, b'')
        self.assertFalse(payload)
        self.assertEqual(remainder, wire)
        self.assertEqual(err, 'timeout')

    def test_rejects_non_json_handshake_without_suffix(self):
        decoded, err = _decode_base64_with_suffix(base64.b64encode(b'garbage') + b'XXEE', b'')
        self.assertIsNone(decoded)
        self.assertEqual(err, 'unexpected_handshake_payload')

    def test_base64_like_next_packet_is_not_consumed(self):
        wire = base64.b64encode(b'{"ErrorNum":"200"}') + b'XXEE'
        next_packet = b'ABCD1234=='
        payload, remainder, err = _recv_base64_message(FakeSocket([wire + next_packet]), 0.5, b'')
        self.assertFalse(err)
        self.assertEqual(payload, wire)
        self.assertEqual(remainder, next_packet)

    def test_explicit_suffix_also_waits_for_fragmented_wire_marker(self):
        encoded = base64.b64encode(b'{"ErrorNum":"200"}')
        payload, remainder, err = _recv_base64_message(
            FakeSocket([encoded, b'XX', b'EE\xff\x01NEXT']), 0.5, b']q\x04')
        self.assertFalse(err)
        self.assertEqual(payload, encoded + b'XXEE')
        self.assertEqual(remainder, b'\xff\x01NEXT')


if __name__ == '__main__':
    unittest.main()
