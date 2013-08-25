# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test import TestCase
from django.test.client import Client

from mockldap import MockLdap

from okupy.tests import vars


class LoginIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_login_page_uses_correct_template(self):
        response = self.client.get('/login/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'login.html')

    def test_correct_user_post_login_redirect(self):
        account = vars.LOGIN_ALICE.copy()
        account['next'] = ''
        response = self.client.post('/login/', account)
        self.assertRedirects(response, '/', 302, 200)

    def test_already_authenticated_user_redirects_to_index(self):
        self.client.post('/login/', vars.LOGIN_ALICE)
        response = self.client.get('/login/')
        self.assertRedirects(response, '/')

    def test_logout_for_logged_in_user_redirects_to_login(self):
        self.client.post('/login/', vars.LOGIN_ALICE)
        response = self.client.get('/logout/')
        self.assertRedirects(response, '/login/')

    def test_logout_for_anonymous_user_redirects_to_login(self):
        response = self.client.get('/logout/')
        self.assertRedirects(response, '/login/')

    def test_logout_no_ldap_doesnt_raise_exception(self):
        self.client.post('/login/', vars.LOGIN_ALICE)
        self.mockldap.stop()
        response = self.client.get('/logout/')
        self.assertRedirects(response, '/login/', 302, 200)
        self.mockldap.start()

    def test_redirect_to_requested_page_after_login(self):
        response = self.client.post('/login/?next=/otp-setup/',
                                    vars.LOGIN_ALICE)
        self.assertRedirects(response, '/otp-setup/', 302, 200)
