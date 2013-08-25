# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.contrib.auth import authenticate, login

from okupy.common.ssh import ssh_handler
from okupy.common.test_helpers import set_request
from okupy.crypto.ciphers import sessionrefcipher
from okupy.otp import init_otp


ssh_handlers = {}


@ssh_handler
def auth(session_id, key):
    try:
        session = sessionrefcipher.decrypt(session_id)
    except ValueError:
        return None

    request = set_request('/')

    user = authenticate(ssh_key=key)
    if user and user.is_active:
        login(request, user)
        init_otp(request)
        session.update(request.session)
        session.save()
        return 'Authenticated.'
    return None
