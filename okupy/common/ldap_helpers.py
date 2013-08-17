# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings

from base64 import b64encode
from Crypto import Random
from passlib.hash import ldap_md5_crypt

from .crypto import cipher
from ..accounts.models import LDAPUser

import edpwd
import ldap


def get_ldap_connection(request=None, username=None, password=None,
                        admin=False):
    if (request and username) or (request and admin) or (username and admin):
        raise TypeError('Please specify one of request, admin or username')

    conn = ldap.initialize(settings.AUTH_LDAP_SERVER_URI)

    for opt, value in settings.AUTH_LDAP_CONNECTION_OPTIONS.items():
        conn.set_option(opt, value)

    if settings.AUTH_LDAP_START_TLS:
        conn.start_tls_s()

    if admin:
        dn = settings.AUTH_LDAP_ADMIN_BIND_DN
        password = settings.AUTH_LDAP_ADMIN_BIND_PASSWORD
    elif request:
        dn = settings.AUTH_LDAP_USER_DN_TEMPLATE % {'user':
                                                    request.user.username}
        password = edpwd.decrypt(settings.SECRET_KEY,
                                 request.session['secondary_password'])
    elif username:
        dn = settings.AUTH_LDAP_USER_DN_TEMPLATE % {'user': username}
    else:
        dn = settings.AUTH_LDAP_BIND_DN
        password = settings.AUTH_LDAP_BIND_PASSWORD

    conn.simple_bind_s(dn, password)
    return conn


def set_secondary_password(request, password):
    """ Generate a secondary passsword and encrypt it in the session """
    settings.DATABASES['ldap']['USER'] = settings.AUTH_LDAP_USER_DN_TEMPLATE \
        % {'user': request.user.username}
    settings.DATABASES['ldap']['PASSWORD'] = password

    user = LDAPUser.objects.get(username=request.user.username)

    secondary_password = Random.get_random_bytes(48)
    request.session['secondary_password'] = cipher.encrypt(secondary_password)
    # Clean up possible leftover secondary passwords from the LDAP account
    if len(user.password) > 1:
        for hash in user.password:
            if not ldap_md5_crypt.verify(password, hash):
                user.password.remove(hash)
    # Add a new generated encrypted password to LDAP
    user.password.append(ldap_md5_crypt.encrypt(b64encode(secondary_password)))
    user.save()


def remove_secondary_password(request):
    """ Remove secondary password on logout """
    settings.DATABASES['ldap']['USER'] = settings.AUTH_LDAP_USER_DN_TEMPLATE \
        % {'user': request.user.username}
    try:
        password = b64encode(cipher.decrypt(
            request.session['secondary_password'], 48))
    except KeyError:
        return
    settings.DATABASES['ldap']['PASSWORD'] = password

    user = LDAPUser.objects.get(username=request.user.username)
    if len(user.password) > 1:
        for hash in user.password:
            if ldap_md5_crypt.verify(password, hash):
                user.password.remove(hash)
    user.save()
