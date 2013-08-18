# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django_otp import oath
from django_otp.models import Device

from base64 import b32decode, b32encode

from ...accounts.models import LDAPUser
from ..models import RevokedToken

import Crypto.Random


class TOTPDevice(Device):
    def is_enabled(self):
        return not self.verify_token()

    def disable(self, user):
        if user.otp_secret:
            user.otp_secret = None
            user.save()

    def enable(self, user, new_secret):
        user.otp_secret = new_secret
        user.save()

    def gen_secret(self):
        rng = Crypto.Random.new()
        return b32encode(rng.read(12)).rstrip('=')

    @staticmethod
    def get_uri(secret):
        return 'otpauth://totp/identity.gentoo.org?secret=%s' % secret

    def verify_token(self, token=None, secret=None):
        if not secret:
            u = LDAPUser.objects.get(username = self.user.username)
            if not u.otp_secret:
                return True
            elif not token: # (we're just being probed)
                return False
            secret = u.otp_secret

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

    class Meta:
        unique_together = ('user',)
