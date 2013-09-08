# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test import TestCase
from django.test.client import Client
from mockldap import MockLdap

from okupy.tests import vars


class SettingsIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_profile_settings_page_uses_correct_template(self):
        response = self.client.post('/login/', vars.LOGIN_ALICE)
        response = self.client.get('/')
        response = self.client.get('/profile-settings/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'settings-profile.html')

    def test_password_settings_page_uses_correct_template(self):
        response = self.client.post('/login/', vars.LOGIN_ALICE)
        response = self.client.get('/')
        response = self.client.get('/password-settings/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'settings-password.html')

    def test_email_settings_page_uses_correct_template(self):
        response = self.client.post('/login/', vars.LOGIN_ALICE)
        response = self.client.get('/')
        response = self.client.get('/email-settings/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'settings-email.html')

    def test_contact_settings_page_uses_correct_template(self):
        response = self.client.post('/login/', vars.LOGIN_ALICE)
        response = self.client.get('/')
        response = self.client.get('/contact-settings/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'settings-contact.html')

    def test_gentoo_account_settings_page_uses_correct_template(self):
        response = self.client.post('/login/', vars.LOGIN_ALICE)
        response = self.client.get('/')
        response = self.client.get('/gentoo-dev-settings/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'settings-gentoo.html')

    def test_profile_settings_page_returns_404_for_non_auth_users(self):
        response = self.client.get('/profile-settings/')
        self.assertTrue(response.status_code, 404)

    def test_password_settings_page_returns_404_for_non_auth_users(self):
        response = self.client.get('/password-settings/')
        self.assertTrue(response.status_code, 404)

    def test_email_settings_page_returns_404_for_non_auth_users(self):
        response = self.client.get('/email-settings/')
        self.assertTrue(response.status_code, 404)

    def test_contact_setttings_page_returns_404_for_non_auth_users(self):
        response = self.client.get('/contact-settings/')
        self.assertTrue(response.status_code, 404)

    def test_gentoo_account_settings_page_returns_404_for_non_auth_users(self):
        response = self.client.get('/gentoo-dev-settings/')
        self.assertTrue(response.status_code, 404)
