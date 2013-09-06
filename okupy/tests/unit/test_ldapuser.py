# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test import TestCase

from base64 import b64encode
from Crypto import Random
from mockldap import MockLdap
from passlib.hash import ldap_md5_crypt

from okupy import OkupyError
from okupy.accounts.models import LDAPUser
from okupy.common.ldap_helpers import get_bound_ldapuser
from okupy.common.test_helpers import ldap_users, set_request
from okupy.crypto.ciphers import cipher
from okupy.tests import vars

import ldap


class LDAPUserUnitTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    def setUp(self):
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_return_unicode_username(self):
        alice = LDAPUser.objects.get(username='alice')
        self.assertEqual(alice.__unicode__(), u'alice')
        self.assertTrue(isinstance(alice.__unicode__(), unicode))

    def test_get_bound_ldapuser_from_request(self):
        secondary_password = Random.get_random_bytes(48)
        secondary_password_crypt = ldap_md5_crypt.encrypt(b64encode(
            secondary_password))
        self.ldapobject.directory[ldap_users('alice')[0]][
            'userPassword'].append(secondary_password_crypt)
        request = set_request('/', user=vars.USER_ALICE)
        request.session['secondary_password'] = cipher.encrypt(
            secondary_password)
        with get_bound_ldapuser(request) as user:
            self.assertEqual(user.username, vars.USER_ALICE.username)

    def test_get_bound_ldapuser_bind_as_is_properly_set_from_request(self):
        secondary_password = Random.get_random_bytes(48)
        secondary_password_crypt = ldap_md5_crypt.encrypt(b64encode(
            secondary_password))
        self.ldapobject.directory[ldap_users('alice')[0]][
            'userPassword'].append(secondary_password_crypt)
        request = set_request('/', user=vars.USER_ALICE)
        request.session['secondary_password'] = cipher.encrypt(
            secondary_password)
        with get_bound_ldapuser(request) as user:  # noqa
            db_alias = 'ldap_%s' % request.session.cache_key
            self.assertEqual(settings.DATABASES[db_alias]['PASSWORD'],
                             b64encode(secondary_password))

    def test_get_bound_ldapuser_bind_as_is_properly_set_from_password(self):
        request = set_request('/', user=vars.USER_ALICE)
        with get_bound_ldapuser(request, password='ldaptest') as user:  # noqa
            db_alias = 'ldap_%s' % request.session.cache_key
            self.assertTrue(ldap_md5_crypt.verify(settings.DATABASES[db_alias][
                'PASSWORD'], ldap_users('alice')[1]['userPassword'][0]))

    def test_get_bound_ldapuser_password_set(self):
        request = set_request('/', user=vars.USER_ALICE)
        with get_bound_ldapuser(request, password='ldaptest') as user:
            self.assertEqual(user.username, vars.USER_ALICE.username)

    def test_get_bound_ldapuser_no_password_available(self):
        request = set_request('/', user=vars.USER_ALICE)
        self.assertRaises(OkupyError, get_bound_ldapuser, request)

    def test_get_bound_ldapuser_invalid_secondary_password(self):
        secondary_password = Random.get_random_bytes(48)
        request = set_request('/', user=vars.USER_ALICE)
        request.session['secondary_password'] = cipher.encrypt(
            secondary_password)
        self.assertRaises(ldap.INVALID_CREDENTIALS, get_bound_ldapuser,
                          request)

    def test_get_bound_ldapuser_invalid_given_password(self):
        request = set_request('/', user=vars.USER_ALICE)
        self.assertRaises(ldap.INVALID_CREDENTIALS, get_bound_ldapuser,
                          request, 'test')

    def test_get_bound_ldapuser_context_manager_cleans_up_settings(self):
        secondary_password = Random.get_random_bytes(48)
        secondary_password_crypt = ldap_md5_crypt.encrypt(b64encode(
            secondary_password))
        self.ldapobject.directory[ldap_users('alice')[0]][
            'userPassword'].append(secondary_password_crypt)
        request = set_request('/', user=vars.USER_ALICE)
        request.session['secondary_password'] = cipher.encrypt(
            secondary_password)
        with get_bound_ldapuser(request) as user:  # noqa
            pass
        db_alias = 'ldap_%s' % request.session.cache_key
        self.assertNotIn(db_alias, settings.DATABASES)
