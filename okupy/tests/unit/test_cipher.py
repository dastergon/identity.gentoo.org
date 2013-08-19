#!/usr/bin/env python

from Crypto import Random
from unittest import TestCase

from ...common.crypto import cipher


class OkupyCipherTests(TestCase):
    def test_verify_password_less_than_8_chars(self):
        hash = cipher.encrypt('test1')
        self.assertEqual(cipher.decrypt(hash, 5), 'test1')

    def test_verify_password_8_chars(self):
        hash = cipher.encrypt('testtest')
        self.assertEqual(cipher.decrypt(hash, 8), 'testtest')

    def test_verify_password_more_than_8_chars(self):
        hash = cipher.encrypt('testtest123')
        self.assertEqual(cipher.decrypt(hash, 11), 'testtest123')

    def test_verify_password_more_than_16_chars(self):
        hash = cipher.encrypt('testtest123456789012')
        self.assertEqual(cipher.decrypt(hash, 20), 'testtest123456789012')

    def test_encrypt_random_bytes(self):
        password = Random.get_random_bytes(45)
        hash = cipher.encrypt(password)
        self.assertEqual(cipher.decrypt(hash, 45), password)
