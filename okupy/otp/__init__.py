# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django_otp import login as otp_login
from django_otp.middleware import OTPMiddleware

from .nootp.models import NoOTPDevice
from .sotp.models import SOTPDevice
from .totp.models import TOTPDevice

def init_otp(request):
    """
    Initialize OTP after login. This sets up OTP devices
    for django_otp and calls the middleware to fill
    request.user.is_verified().
    """

    nodev, created = NoOTPDevice.objects.get_or_create(
        user=request.user,
        defaults={
            'name': 'OTP-disabled pass-through',
        })
    if created:
        nodev.save()

    tdev, created = TOTPDevice.objects.get_or_create(
        user=request.user,
        defaults={
            'name': 'TOTP device with LDAP secret',
        })
    if created:
        tdev.save()

    sdev, created = SOTPDevice.objects.get_or_create(
        user=request.user,
        defaults={
            'name': 'SOTP device with LDAP passwords',
        })
    if created:
        sdev.save()

    # nootp may match already
    if nodev.verify_token():
        otp_login(request, nodev)

    # add .is_verified()
    OTPMiddleware().process_request(request)
