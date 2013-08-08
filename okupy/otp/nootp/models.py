# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django_otp.models import Device

from ..totp.models import TOTPDevice

class NoOTPDevice(Device):
    """ A fake OTP device that successfully verifies token
    if user has OTP disabled. """

    def verify_token(self, token=None):
        return not TOTPDevice.objects.get(user=self.user).is_enabled()
