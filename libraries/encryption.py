from Crypto.Cipher import Blowfish
from django.conf import settings
from random import choice
from base64 import encodestring as encode
from base64 import decodestring as decode
import base64
import hashlib
import string
import os

def sha_password(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + encode(h.digest() + salt)[:-1]

def check_password(challenge_password, password,):
    challenge_bytes = decode(challenge_password[6:])
    digest = challenge_bytes[:20]
    salt = challenge_bytes[20:]
    hr = hashlib.sha1(password)
    hr.update(salt)
    return digest == hr.digest()

def encrypt_password(password):
    obj = Blowfish.new(settings.BLOWFISH_KEY)
    return base64.b64encode(obj.encrypt(password + settings.SECRET_KEY[:8]))

def decrypt_password(password):
    obj = Blowfish.new(settings.BLOWFISH_KEY)
    original_password = obj.decrypt(base64.b64decode(password + settings.SECRET_KEY[:8]))
    return original_password[:-8]

def random_string(length, type = None):
    if type == 'password':
        chars = string.printable[:-6]
    else:
        chars = string.letters + string.digits
    return ''.join([choice(chars) for i in range(length)])
