# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from ..accounts.models import LDAPUser

from OpenSSL.crypto import load_certificate, FILETYPE_PEM


class SSLCertAuthBackend(ModelBackend):
    """
    Authentication backend taht uses client certificate information.
    It requires one of owner e-mails to match in LDAP.
    """

    def authenticate(self, request=None):
        if request is None:
            return None

        # it can be: SUCCESS, NONE and likely some string for failure ;)
        cert_verify = request.META.get('SSL_CLIENT_VERIFY', None)
        if cert_verify != 'SUCCESS':
            return None

        # curious enough, it's easier to parse the whole certificate
        # than DN obtained from it by nginx...
        cert = load_certificate(FILETYPE_PEM,
                                request.META['SSL_CLIENT_RAW_CERT'])
        dn = cert.get_subject().get_components()

        # for multiple addresses, there are multiple emailAddress fields
        for k, v in dn:
            if k == 'emailAddress':
                try:
                    u = LDAPUser.objects.get(email__contains=v)
                except LDAPUser.DoesNotExist:
                    pass
                else:
                    UserModel = get_user_model()
                    user, created = UserModel.objects.get_or_create(**{
                        UserModel.USERNAME_FIELD: u.username
                    })
                    return user
        return None
