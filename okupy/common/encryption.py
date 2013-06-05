from Crypto.Cipher import Blowfish
from django.conf import settings
from random import choice
import base64
import hashlib
import os
import string

def encrypt_password(password):
    '''
    Encrypt the password in Blowfish encryption, using the secret key
    specified in the settings file
    '''
    obj = Blowfish.new(settings.SECRET_KEY)
    return base64.b64encode(obj.encrypt(password + settings.SECRET_KEY[:8]))

def decrypt_password(password):
    '''
    Decrypt the password in Blowfish encryption, using the secret key
    specified in the settings file
    '''
    obj = Blowfish.new(settings.SECRET_KEY)
    origin_pass = obj.decrypt(base64.b64decode(password + settings.SECRET_KEY[:8]))
    return origin_pass[:-8]

def random_string(length):
    '''
    Returns a random string for temporary URLs
    '''
    return ''.join([choice(string.letters + string.digits) for i in range(length)])
