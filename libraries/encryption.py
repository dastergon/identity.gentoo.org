from Crypto.Cipher import Blowfish
from django.conf import settings
from random import choice
from base64 import encodestring as encode
import base64
import hashlib
import string
import os

def sha1Password(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + encode(h.digest() + salt)

def encryptPassword(password):
    obj = Blowfish.new(settings.BLOWFISH_KEY)
    return base64.b64encode(obj.encrypt(password))

def decryptPassword(password):
    obj = Blowfish.new(settings.BLOWFISH_KEY)
    original_password = obj.decrypt(base64.b64decode(password))
    return original_password

def random_string(length, type = None):
    if type == 'password':
        chars = string.printable[:-6]
    else:
        chars = string.letters + string.digits
    return ''.join([choice(chars) for i in range(length)])
