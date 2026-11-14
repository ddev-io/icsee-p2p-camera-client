"""Device password login framing reconstructed from FunSDK RSAV15()."""
import unittest

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from xmplayer.core.legacy_api import build_6611_login_candidate, _xm_md5_encrypt_value


class DevicePasswordLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = RSA.generate(1024)
        cls.public_key = f'{cls.private_key.n:X},{cls.private_key.e:X}'

    def decrypt(self, value):
        return PKCS1_v1_5.new(self.private_key).decrypt(bytes.fromhex(value), b'invalid').decode()

    def test_rsa_wrapped_credentials_keep_native_md5_type(self):
        result = build_6611_login_candidate(
            claim_source={'EncryptAlgo': 'RSA_V1.5', 'PublicKey': self.public_key,
                          'LoginEncryptionType': {'MD5': True}, 'DataEncryptionType': {'AES': True}},
            mode='password', username='admin', password='test-camera-password',
            communicate_key='1234567890abcdef')
        self.assertEqual(result['status'], 'ok')
        body = result['candidate_json']
        self.assertEqual(body['EncryptType'], 'MD5')
        self.assertEqual(self.decrypt(body['UserName']), 'admin')
        self.assertEqual(self.decrypt(body['PassWord']), _xm_md5_encrypt_value('test-camera-password'))
        self.assertEqual(self.decrypt(body['CommunicateKey']), '1234567890abcdef')

    def test_plain_md5_password_uses_known_empty_password_wire_value(self):
        result = build_6611_login_candidate(
            claim_source={'LoginEncryptionType': {'MD5': True}},
            mode='password', username='admin', password='')
        self.assertEqual(result['candidate_json']['EncryptType'], 'MD5')
        self.assertEqual(result['candidate_json']['PassWord'], 'tlJwpbo6')

    def test_token_login_is_preserved_when_rsa_is_advertised(self):
        result = build_6611_login_candidate(
            claim_source={'EncryptAlgo': 'RSA_V1.5', 'PublicKey': self.public_key,
                          'LoginEncryptionType': {'MD5': True, 'TOKEN': True}},
            mode='token', username='', password='', admin_token='reference-device-token',
            token_username='reference-device-token', login_type='DVRIP-Xm030')
        self.assertEqual(result['candidate_json']['EncryptType'], 'TOKEN')
        self.assertEqual(result['candidate_json']['UserName'], 'reference-device-token')
        self.assertEqual(result['candidate_json']['PassWord'], '')


if __name__ == '__main__':
    unittest.main()
