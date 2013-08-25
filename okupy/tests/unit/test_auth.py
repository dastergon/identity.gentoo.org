# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from mockldap import MockLdap

from django.conf import settings
from django.contrib.auth import authenticate

from .. import vars
from ...common.test_helpers import OkupyTestCase, set_request


class AuthUnitTests(OkupyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    def setUp(self):
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_valid_certificate_authenticates_alice(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'SUCCESS'
        request.META['SSL_CLIENT_RAW_CERT'] = vars.TEST_CERTIFICATE

        u = authenticate(request=request)
        self.assertEqual(u.username, vars.LOGIN_ALICE['username'])

    def test_second_email_authenticates_alice(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'SUCCESS'
        request.META['SSL_CLIENT_RAW_CERT'] = (
            vars.TEST_CERTIFICATE_WITH_TWO_EMAIL_ADDRESSES)

        u = authenticate(request=request)
        self.assertEqual(u.username, vars.LOGIN_ALICE['username'])

    def test_no_certificate_returns_none(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'NONE'

        u = authenticate(request=request)
        self.assertIs(u, None)

    def test_failed_verification_returns_none(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'FAILURE'
        request.META['SSL_CLIENT_RAW_CERT'] = vars.TEST_CERTIFICATE

        u = authenticate(request=request)
        self.assertIs(u, None)

    def test_unmatched_email_returns_none(self):
        request = set_request(uri='/login')
        request.META['SSL_CLIENT_VERIFY'] = 'SUCCESS'
        request.META['SSL_CLIENT_RAW_CERT'] = vars.TEST_CERTIFICATE_WRONG_EMAIL

        u = authenticate(request=request)
        self.assertIs(u, None)
