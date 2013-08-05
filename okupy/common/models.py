# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.db import models

from Crypto.Cipher.AES import AESCipher
from Crypto.Hash.SHA256 import SHA256Hash

import binascii
import random
import struct


class IDCipher(object):
    def __init__(self):
        hasher = SHA256Hash()
        hasher.update(settings.SECRET_KEY)
        key_hash = hasher.digest()
        self.cipher = AESCipher(key_hash)

    def encrypt(self, id):
        # pack the id and some random data to prevent attacks
        # trying to guess the SECRET_KEY with guessed ids
        byte_id = struct.pack('!QQ', id, random.getrandbits(64))
        byte_eid = self.cipher.encrypt(byte_id)
        return binascii.b2a_hex(byte_eid)

    def decrypt(self, eid):
        byte_eid = binascii.a2b_hex(eid)
        byte_id = self.cipher.decrypt(byte_eid)
        id, rand = struct.unpack('!QQ', byte_id)
        return id

idcipher = IDCipher()


# based on https://gist.github.com/treyhunner/735861

class EncryptedPKModelManager(models.Manager):
    def get(self, *args, **kwargs):
        eid = kwargs.pop('encrypted_id', None)
        if eid is not None:
            kwargs['id'] = idcipher.decrypt(eid)
        return super(EncryptedPKModelManager, self).get(*args, **kwargs)


class EncryptedPKModel(models.Model):
    objects = EncryptedPKModelManager()

    @property
    def encrypted_id(self):
        if self.id is None:
            return None
        return idcipher.encrypt(self.id)

    class Meta:
        abstract = True
