# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from Crypto import Random
from unittest import TestCase, SkipTest

from django.contrib.sessions.backends.cache import SessionStore

from ...crypto.ciphers import cipher, sessionrefcipher


class OkupyCipherTests(TestCase):
    def setUp(self):
        self._random_string = '123456abcdef' * int(cipher.block_size / 2)

    def test_verify_password_less_than_block_size(self):
        data = self._random_string[:cipher.block_size-3]
        hash = cipher.encrypt(data)
        self.assertEqual(cipher.decrypt(hash, len(data)), data)

    def test_verify_password_exact_block_size(self):
        data = self._random_string[:cipher.block_size]
        hash = cipher.encrypt(data)
        self.assertEqual(cipher.decrypt(hash, len(data)), data)

    def test_verify_password_more_than_block_size(self):
        data = self._random_string[:cipher.block_size+3]
        hash = cipher.encrypt(data)
        self.assertEqual(cipher.decrypt(hash, len(data)), data)

    def test_verify_password_more_than_twice_block_size(self):
        data = self._random_string[:cipher.block_size*2+3]
        hash = cipher.encrypt(data)
        self.assertEqual(cipher.decrypt(hash, len(data)), data)

    def test_encrypt_random_bytes(self):
        data = Random.get_random_bytes(45)
        hash = cipher.encrypt(data)
        self.assertEqual(cipher.decrypt(hash, len(data)), data)

    def test_ciphertext_shorter_than_req_output_raises_valueerror(self):
        data = self._random_string[:cipher.block_size*2]
        hash = cipher.encrypt(data)[:cipher.block_size]
        self.assertRaises(ValueError, cipher.decrypt, hash, len(data))

    def test_ciphertext_not_multiple_of_block_size_raises_valueerror(self):
        data = self._random_string[:cipher.block_size/2]
        hash = cipher.encrypt(data)[:cipher.block_size/2]
        self.assertRaises(ValueError, cipher.decrypt, hash, len(data))


class SessionRefCipherTest(TestCase):
    def test_encrypt_decrypt(self):
        session = SessionStore()
        session['test'] = 'in-test'
        session.save()

        eid = sessionrefcipher.encrypt(session)
        sess = sessionrefcipher.decrypt(eid)
        self.assertEqual(sess.get('test'), 'in-test')

    def test_invalid_base64_raises_valueerror(self):
        data = 'Azcd^%'
        self.assertRaises(ValueError, sessionrefcipher.decrypt, data)

    def test_invalid_ciphertext_raises_valueerror(self):
        data = 'ZHVwYQo='
        self.assertRaises(ValueError, sessionrefcipher.decrypt, data)

    def test_unique_encrypted_are_generated_after_revocation(self):
        session = SessionStore()
        session['test'] = 'in-test'
        session.save()

        eid1 = sessionrefcipher.encrypt(session)
        session = sessionrefcipher.decrypt(eid1)
        eid2 = sessionrefcipher.encrypt(session)
        self.assertNotEqual(eid1, eid2)

    def test_revoked_encrypted_id_raises_valueerror(self):
        session = SessionStore()
        session['test'] = 'in-test'
        session.save()

        eid1 = sessionrefcipher.encrypt(session)
        session = sessionrefcipher.decrypt(eid1)
        eid2 = sessionrefcipher.encrypt(session)
        if eid1 == eid2:
            raise SkipTest('Non-unique encrypted IDs generated')
        self.assertRaises(ValueError, sessionrefcipher.decrypt, eid1)
