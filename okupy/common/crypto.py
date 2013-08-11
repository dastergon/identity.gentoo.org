# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings

from Crypto.Cipher.Blowfish import BlowfishCipher
from Crypto.Hash.SHA384 import SHA384Hash

import Crypto.Random

import binascii
import struct


class OkupyCipher(object):
    """ Symmetric cipher using django's SECRET_KEY. """

    _hasher_algo = SHA384Hash
    _cipher_algo = BlowfishCipher
    _cipher_block_size = 8

    def __init__(self):
        hasher = self._hasher_algo()
        hasher.update(settings.SECRET_KEY)
        key_hash = hasher.digest()
        self.cipher = self._cipher_algo(key_hash)
        self.rng = Crypto.Random.new()

    def encrypt(self, data):
        """
        Encrypt random-length data block padding it with random data
        if necessary.
        """

        # minus is intentional. (-X % S) == S - (X % S)
        padding = -len(data) % self._cipher_block_size
        if padding:
            data += self.rng.read(padding)
        return self.cipher.encrypt(data)

    def decrypt(self, data, length):
        """
        Decrypt the data block of given length. Removes padding if any.
        """

        return self.cipher.decrypt(data)[:length]


cipher = OkupyCipher()


class IDCipher(object):
    def encrypt(self, id):
        byte_id = struct.pack('!I', id)
        byte_eid = cipher.encrypt(byte_id)
        return binascii.b2a_hex(byte_eid)

    def decrypt(self, eid):
        byte_eid = binascii.a2b_hex(eid)
        byte_id = cipher.decrypt(byte_eid, 4)
        id = struct.unpack('!I', byte_id)[0]
        return id


idcipher = IDCipher()
