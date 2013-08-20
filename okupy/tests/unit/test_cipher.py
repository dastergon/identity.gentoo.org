# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from Crypto import Random
from unittest import TestCase

from ...common.crypto import cipher


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
