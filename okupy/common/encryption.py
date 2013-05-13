from Crypto.Cipher import AES
from django.conf import settings
from random import choice
import base64
import hashlib
import os
import string

def sha1_password(password):
    '''
    Create a SHA1 salted hash
    '''
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + base64.encodestring(h.digest() + salt)[:-1]

def check_password(challenge_password, password,):
    challenge_bytes = decode(challenge_password[6:])
    digest = challenge_bytes[:20]
    salt = challenge_bytes[20:]
    hr = hashlib.sha1(password)
    hr.update(salt)
    return digest == hr.digest()

def encrypt_password(password):
    '''
    Encrypt the password in AES encryption, using the secret key
    specified in the settings file
    Taken from
    http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
    '''
    BLOCK_SIZE = 32
    PADDING = '{'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    cipher = AES.new(settings.SECRET_KEY[:BLOCK_SIZE])
    return EncodeAES(cipher, password)

def decrypt_password(password):
    '''
    Decrypt the password in AES encryption, using the secret key
    specified in the settings file
    Taken from
    http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
    '''
    BLOCK_SIZE = 32
    PADDING = '{'
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
    cipher = AES.new(settings.SECRET_KEY[:BLOCK_SIZE])
    return DecodeAES(cipher, password)

def random_string(length):
    '''
    Returns a random string for temporary URLs
    '''
    return ''.join([choice(string.letters + string.digits) for i in range(length)])
