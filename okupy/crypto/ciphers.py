# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.sessions.backends.cache import SessionStore

from Crypto.Cipher.AES import AESCipher
from Crypto.Hash.SHA256 import SHA256Hash

import Crypto.Random

import struct

from okupy.crypto.codecs import ub64encode, ub64decode


class OkupyCipher(object):
    """ Symmetric cipher using django's SECRET_KEY. """

    _hasher_algo = SHA256Hash
    _cipher_algo = AESCipher

    def __init__(self):
        hasher = self._hasher_algo()
        hasher.update(settings.SECRET_KEY)
        key_hash = hasher.digest()
        self.cipher = self._cipher_algo(key_hash)
        self.rng = Crypto.Random.new()

    @property
    def block_size(self):
        """
        Cipher's block size.
        """
        return self.cipher.block_size

    def encrypt(self, data):
        """
        Encrypt random-length data block padding it with random data
        if necessary.
        """

        # ensure it's bytestring before we append random bits
        data = bytes(data)
        # minus is intentional. (-X % S) == S - (X % S)
        padding = -len(data) % self.block_size
        if padding:
            data += self.rng.read(padding)
        return self.cipher.encrypt(data)

    def decrypt(self, data, length):
        """
        Decrypt the data block of given length. Removes padding if any.
        """

        if len(data) < length:
            raise ValueError('Ciphertext too short for requested length')
        return self.cipher.decrypt(data)[:length]


class IDCipher(object):
    """
    A cipher to create 'encrypted database IDs'. It is specifically fit
    to encrypt an integer into constant-length hexstring.
    """

    def encrypt(self, id):
        byte_id = struct.pack('!I', id)
        byte_eid = cipher.encrypt(byte_id)
        return ub64encode(byte_eid)

    def decrypt(self, eid):
        byte_eid = ub64decode(eid)
        byte_id = cipher.decrypt(byte_eid, 4)
        id = struct.unpack('!I', byte_id)[0]
        return id


class SessionRefCipher(object):
    """
    A cipher to provide encrypted identifiers to sessions.

    The encrypted session ID is stored in session for additional
    security. Only previous encryption result may be used in decrypt().
    """

    cache_key_prefix = 'django.contrib.sessions.cache'
    session_id_length = 32
    random_prefix_bytes = 4
    ciphertext_length = session_id_length*3/4 + random_prefix_bytes

    def encrypt(self, session):
        """
        Return an encrypted reference to the session. The encrypted
        identifier will be stored in the session for verification
        and caching. Therefore, further calls to this method will reuse
        the previously cached identifier.
        """

        if 'encrypted_id' not in session:
            # .cache_key is a very good property since it ensures
            # that the cache is actually created, and works from first
            # request
            session_id = session.cache_key

            # since it always starts with the backend module name
            # and __init__() expects pure id, we can strip that
            assert(session_id.startswith(self.cache_key_prefix))
            session_id = session_id[len(self.cache_key_prefix):]
            assert(len(session_id) == self.session_id_length)

            # now's another curious trick: session id consists
            # of [a-z][0-9]. it's basically base36 but since decoding
            # that is harsh, let's just treat it as base64. that's
            # going to pack it into 3/4 original size, that is 24 bytes.
            # then, with random prefix prepended we will fit into one
            # block of ciphertext less.
            session_id = ub64decode(session_id)

            data = (cipher.rng.read(self.random_prefix_bytes)
                    + session_id)
            assert(len(data) == self.ciphertext_length)
            session['encrypted_id'] = ub64encode(
                cipher.encrypt(data))
            session.save()
        return session['encrypted_id']

    def decrypt(self, eid):
        """
        Return the SessionStore to which the encrypted identifier is
        pointing. Raises ValueError if the identifier is invalid.
        """

        try:
            session_id = cipher.decrypt(ub64decode(eid),
                                        self.ciphertext_length)
        except (TypeError, ValueError):
            pass
        else:
            session_id = session_id[self.random_prefix_bytes:]
            session_id = ub64encode(session_id)
            session = SessionStore(session_key=session_id)
            if session.get('encrypted_id') == eid:
                # circular import
                from .models import RevokedToken

                # revoke to prevent replay attacks
                if RevokedToken.add(eid):
                    del session['encrypted_id']
                    session.save()
                    return session
        raise ValueError('Invalid session id')


cipher = OkupyCipher()
idcipher = IDCipher()
sessionrefcipher = SessionRefCipher()
