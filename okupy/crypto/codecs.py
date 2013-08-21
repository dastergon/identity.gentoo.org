# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

import base64


def ub32encode(text):
    """ Encode text as unpadded base32. """
    return base64.b32encode(text).rstrip('=')


def ub32decode(text):
    """ Decode text from unpadded base32. """
    # add missing padding if necessary
    text += '=' * (-len(text) % 8)
    return base64.b32decode(text, casefold=True)


def ub64encode(text):
    """ Encode text as unpadded, url-safe base64. """
    return base64.urlsafe_b64encode(text).rstrip('=')


def ub64decode(text):
    """ decode text from unpadded, url-safe base64. """
    # add missing padding if necessary
    text += '=' * (-len(text) % 4)
    return base64.urlsafe_b64decode(bytes(text))
