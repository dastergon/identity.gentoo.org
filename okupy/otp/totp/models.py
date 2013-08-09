# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.contrib.auth.models import User
from django.db import models

from django_otp import oath
from django_otp.models import Device

from base64 import b32decode, b32encode

from ..models import RevokedToken

import Crypto.Random


class TOTPSecret(models.Model):
    user = models.ForeignKey(User)
    # TODO: move to LDAPUser
    secret = models.CharField(max_length=20, default='adgg',
        help_text='A base32-encoded secret key')


class TOTPDevice(Device):
    def _get_secret(self):
        try:
            o = TOTPSecret.objects.get(user=self.user)
        except TOTPSecret.DoesNotExist:
            return None
        return o

    def is_enabled(self):
        return bool(self._get_secret())

    def disable(self):
        o = self._get_secret()
        if not o:
            return
        o.delete()

    def enable(self, new_secret):
        o = self._get_secret()
        if not o:
            o = TOTPSecret(user=self.user)
        o.secret = new_secret
        o.save()

    def gen_secret(self):
        rng = Crypto.Random.new()
        return b32encode(rng.read(12)).rstrip('=')

    @staticmethod
    def get_uri(secret):
        return 'otpauth://totp/identity.gentoo.org?secret=%s' % secret

    def verify_token(self, token=None, secret=None):
        if not secret:
            o = self._get_secret()
            if not o:
                return True
            elif not token: # (we're just being probed)
                return False
            secret = o.secret

        # prevent replay attacks
        if not RevokedToken.add(self.user, token):
            return False

        # add missing padding if necessary
        secret += '=' * (-len(secret) % 8)

        key = b32decode(secret, casefold=True)
        try:
            token = int(token)
        except ValueError:
            return False

        for offset in range(-2, 3):
            if oath.totp(key, drift=offset) == token:
                return True
        return False
