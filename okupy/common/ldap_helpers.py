# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
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
                                 request.user.secondary_password)
    elif username:
        dn = settings.AUTH_LDAP_USER_DN_TEMPLATE % {'user': username}
    else:
        dn = settings.AUTH_LDAP_BIND_DN
        password = settings.AUTH_LDAP_BIND_PASSWORD

    conn.simple_bind_s(dn, password)
    return conn
