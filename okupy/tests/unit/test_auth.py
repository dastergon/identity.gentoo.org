# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from mockldap import MockLdap

from django.conf import settings
from django.contrib.auth import authenticate
from django.test.utils import override_settings

from .. import vars
from ...common.test_helpers import OkupyTestCase, set_request, ldap_users, set_search_seed


class AuthUnitTests(OkupyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    def setUp(self):
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    @override_settings(AUTHENTICATION_BACKENDS=(
        'okupy.common.auth.SSLCertAuthBackend',))
    def test_valid_certificate_authenticates_alice(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'SUCCESS'
        request.META['SSL_CLIENT_RAW_CERT'] = vars.test_certificate

        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice@test.com', 'mail'))([ldap_users('alice')])
        u = authenticate(request=request)
        self.assertEqual(u.username, vars.LOGIN_ALICE['username'])

    @override_settings(AUTHENTICATION_BACKENDS=(
        'okupy.common.auth.SSLCertAuthBackend',))
    def test_second_email_authenticates_alice(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'SUCCESS'
        request.META['SSL_CLIENT_RAW_CERT'] = (
            vars.test_certificate_with_two_email_addresses)

        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('test@test.com', 'mail'))([])
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice@test.com', 'mail'))([ldap_users('alice')])
        u = authenticate(request=request)
        self.assertEqual(u.username, vars.LOGIN_ALICE['username'])

    @override_settings(AUTHENTICATION_BACKENDS=(
        'okupy.common.auth.SSLCertAuthBackend',))
    def test_no_certificate_returns_none(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'NONE'

        u = authenticate(request=request)
        self.assertIs(u, None)

    @override_settings(AUTHENTICATION_BACKENDS=(
        'okupy.common.auth.SSLCertAuthBackend',))
    def test_failed_verification_returns_none(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'FAILURE'
        request.META['SSL_CLIENT_RAW_CERT'] = vars.test_certificate

        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice@test.com', 'mail'))([ldap_users('alice')])
        u = authenticate(request=request)
        self.assertIs(u, None)

    @override_settings(AUTHENTICATION_BACKENDS=(
        'okupy.common.auth.SSLCertAuthBackend',))
    def test_unmatched_email_returns_none(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'SUCCESS'
        request.META['SSL_CLIENT_RAW_CERT'] = vars.test_certificate_wrong_email

        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('wrong@test.com', 'mail'))([])
        u = authenticate(request=request)
        self.assertIs(u, None)
