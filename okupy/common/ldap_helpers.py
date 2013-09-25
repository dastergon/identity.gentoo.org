# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from base64 import b64encode
from Crypto import Random
from passlib.hash import ldap_md5_crypt

from okupy import OkupyError
from okupy.accounts.models import LDAPUser
from okupy.crypto.ciphers import cipher


def get_bound_ldapuser(request, password=None, username=None):
    """
    Get LDAPUser with connection bound to the current user.
    Uses either provided password or the secondary password saved
    in session.
    """
    if not username:
        username = request.user.username
    if not password:
        try:
            password = b64encode(cipher.decrypt(
                request.session['secondary_password'], 48))
        except KeyError:
            raise OkupyError(
                'Secondary password not available (no strong auth?)')

    bound_cls = LDAPUser.bind_as(
        alias='ldap_%s' % request.session.cache_key,
        username=username,
        password=password,
    )
    try:
        return bound_cls.objects.get(username=username)
    except Exception as e:
        bound_cls.restore_alias()
        raise e


def set_secondary_password(request, password):
    """ Generate a secondary passsword and encrypt it in the session """
    with get_bound_ldapuser(request, password) as user:
        secondary_password = Random.get_random_bytes(48)
        request.session['secondary_password'] = \
            cipher.encrypt(secondary_password)
        # Clean up possible leftover secondary passwords from the LDAP account
        if len(user.password) > 1:
            for hash in list(user.password):
                try:
                    if not ldap_md5_crypt.verify(password, hash):
                        user.password.remove(hash)
                except ValueError:
                    # don't remove unknown hashes
                    pass
        # Add a new generated encrypted password to LDAP
        user.password.append(
            ldap_md5_crypt.encrypt(b64encode(secondary_password)))
        user.save()


def remove_secondary_password(request):
    """ Remove secondary password on logout """
    try:
        password = b64encode(cipher.decrypt(
            request.session['secondary_password'], 48))
    except KeyError:
        return

    with get_bound_ldapuser(request, password) as user:
        if len(user.password) > 1:
            for hash in list(user.password):
                try:
                    if ldap_md5_crypt.verify(password, hash):
                        user.password.remove(hash)
                        break
                except ValueError:
                    # ignore unknown hashes
                    pass
        user.save()
