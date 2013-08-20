# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.sessions.backends.cache import SessionStore

from Crypto.Cipher.Blowfish import BlowfishCipher
from Crypto.Hash.SHA384 import SHA384Hash

import Crypto.Random

import base64
import struct


def ub32encode(text):
    """ Encode text as unpadded base32. """
    return base64.b32encode(text).rstrip('=')


def ub32decode(text):
    """ Decode text from unpadded base32. """
    # add missing padding if necessary
    text += '=' * (-len(text) % 8)
    return base64.b32decode(text, casefold=True)


class OkupyCipher(object):
    """ Symmetric cipher using django's SECRET_KEY. """

    _hasher_algo = SHA384Hash
    _cipher_algo = BlowfishCipher

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
        return ub32encode(byte_eid).lower()

    def decrypt(self, eid):
        byte_eid = ub32decode(eid)
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

            data = (cipher.rng.read(self.random_prefix_bytes)
                    + session_id.encode('utf8'))
            session['encrypted_id'] = ub32encode(
                cipher.encrypt(data)).lower()
            session.save()
        return session['encrypted_id']

    def decrypt(self, eid):
        """
        Return the SessionStore to which the encrypted identifier is
        pointing. Raises ValueError if the identifier is invalid.
        """

        try:
            session_id = cipher.decrypt(ub32decode(eid),
                                        self.session_id_length
                                        + self.random_prefix_bytes)
        except (TypeError, ValueError):
            pass
        else:
            session_id = session_id[self.random_prefix_bytes:]
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
