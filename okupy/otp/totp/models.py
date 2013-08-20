# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django_otp import oath
from django_otp.models import Device

from ...accounts.models import LDAPUser
from ...common.crypto import ub32decode, ub32encode

import Crypto.Random


class TOTPDevice(Device):
    """
    OTP device that verifies against a TOTP-generated token.
    """

    def is_enabled(self):
        """
        Check whether TOTP is enabled.

        Returns True if user has TOTP secret set, False otherwise.
        """
        return not self.verify_token()

    def disable(self, user):
        """
        Disable TOTP. Removes the secret from LDAP.
        """
        if user.otp_secret:
            user.otp_secret = None
            user.save()

    def enable(self, user, new_secret):
        """
        Enable TOTP. Saves the secret to LDAP.
        """
        user.otp_secret = new_secret
        user.save()

    def gen_secret(self):
        """
        Generate a new TOTP secret compliant with Google Authenticator.

        Returns 20-character base32 string (with padding stripped).
        """
        rng = Crypto.Random.new()
        return ub32encode(rng.read(12))

    @staticmethod
    def get_uri(secret):
        """
        Get otpauth:// URI for secret transfer.
        """
        return 'otpauth://totp/gentoo.org?secret=%s' % secret

    def verify_token(self, token=None, secret=None):
        """
        Verify the entered token against current TOTP token, and the few
        past and future tokens to include clock drift.
        """
        if not secret:
            u = LDAPUser.objects.get(username = self.user.username)
            if not u.otp_secret:
                return True
            elif not token: # (we're just being probed)
                return False
            secret = u.otp_secret

        key = ub32decode(secret)
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
