from base64 import encodestring as encode
import base64
import hashlib
import os

def sha1Password(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + encode(h.digest() + salt)