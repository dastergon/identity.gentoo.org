# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.db import IntegrityError
from django_otp import login as otp_login
from django_otp.middleware import OTPMiddleware

from .sotp.models import SOTPDevice
from .totp.models import TOTPDevice

def init_otp(request):
    """
    Initialize OTP after login. This sets up OTP devices
    for django_otp and calls the middleware to fill
    request.user.is_verified().
    """

    tdev = TOTPDevice(user=request.user,
                      name='TOTP device with LDAP secret')
    try:
        tdev.save()
    except IntegrityError:
        tdev = TOTPDevice.objects.get(user=request.user)

    sdev = SOTPDevice(user=request.user,
                      name='SOTP device with LDAP secret')
    try:
        sdev.save()
    except IntegrityError:
        pass

    # if OTP is disabled, it will match already
    if tdev.verify_token():
        otp_login(request, tdev)

    # add .is_verified()
    OTPMiddleware().process_request(request)
