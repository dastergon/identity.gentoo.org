# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db import IntegrityError

from okupy.accounts.models import LDAPUser
from okupy.common.ldap_helpers import get_bound_ldapuser

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

import ldap
import paramiko

import base64


class LDAPAuthBackend(ModelBackend):
    """
    Authentication backend that authenticates against LDAP password.
    If authentication succeeds, it sets up secondary password
    for the session.
    """

    def authenticate(self, request, username, password):
        # LDAP is case- and whitespace-insensitive
        # we do normalization to avoid duplicate django db entries
        # and help mockldap
        username = username.lower().strip()

        try:
            bound_ldapuser = get_bound_ldapuser(
                request=request,
                username=username,
                password=password)

            with bound_ldapuser as u:
                UserModel = get_user_model()
                attr_dict = {
                    UserModel.USERNAME_FIELD: u.username
                }

                user = UserModel(**attr_dict)
                try:
                    user.save()
                except IntegrityError:
                    user = UserModel.objects.get(**attr_dict)
                return user
        except ldap.INVALID_CREDENTIALS:
            return None
        except ldap.STRONG_AUTH_REQUIRED:
            return None


class SSLCertAuthBackend(ModelBackend):
    """
    Authentication backend taht uses client certificate information.
    It requires one of owner e-mails to match in LDAP.
    """

    def authenticate(self, request):
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
                    attr_dict = {
                        UserModel.USERNAME_FIELD: u.username
                    }

                    user = UserModel(**attr_dict)
                    try:
                        user.save()
                    except IntegrityError:
                        user = UserModel.objects.get(**attr_dict)
                    return user
        return None


class SSHKeyAuthBackend(ModelBackend):
    """
    Authentication backend that uses SSH keys stored in LDAP.
    """

    def authenticate(self, ssh_key=None):
        for u in LDAPUser.objects.all():
            for k in u.ssh_key:
                spl = k.split()
                if len(spl) < 2:
                    continue

                form, user_key = spl[:2]
                if form == 'ssh-rsa':
                    key_class = paramiko.RSAKey
                elif form == 'ssh-dss':
                    key_class = paramiko.DSSKey
                else:
                    # key format not supported
                    continue

                try:
                    user_key = key_class(data=base64.b64decode(user_key))
                except (TypeError, paramiko.SSHException):
                    continue

                # paramiko reconstructs the key, so simple match should be fine
                if ssh_key == user_key:
                    UserModel = get_user_model()
                    attr_dict = {
                        UserModel.USERNAME_FIELD: u.username
                    }

                    user = UserModel(**attr_dict)
                    try:
                        user.save()
                    except IntegrityError:
                        user = UserModel.objects.get(**attr_dict)
                    return user
        return None
