# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test import TestCase
from django.test.client import Client
from mockldap import MockLdap

from .. import vars
from ...accounts.models import LDAPUser
from ...common.test_helpers import set_search_seed, ldap_users


class SignupIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_signup_page_uses_correct_template(self):
        response = self.client.get('/signup/')
        self.assertTemplateUsed(response, 'signup.html')

    def test_wrong_activation_link_redirects_to_login(self):
        vars.QUEUEDUSER.save()
        response = self.client.get('/activate/invalidurl/')
        self.assertRedirects(response, '/login/', 302, 200)

    def test_valid_data_to_signup_redirects_to_login(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('testuser'))(LDAPUser.DoesNotExist)
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('test@test.com', attr='mail'))(LDAPUser.DoesNotExist)
        response = self.client.post('/signup/', vars.SIGNUP_TESTUSER)
        self.assertRedirects(response, '/login/', 302, 200)

    def test_logged_in_user_signup_url_redirects_to_index(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([ldap_users('alice')])
        self.client.post('/login/', {'username': 'alice', 'password': 'ldaptest'})
        response = self.client.get('/signup/')
        self.assertRedirects(response, '/', 302, 200)

    def test_logged_in_user_activate_url_redirects_to_index(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([ldap_users('alice')])
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed())(ldap_users(all=True))
        vars.QUEUEDUSER.save()
        activate_url = '/activate/%s/' % vars.QUEUEDUSER.encrypted_id
        self.client.post('/login/', {'username': 'alice', 'password': 'ldaptest'})
        response = self.client.get(activate_url)
        self.assertRedirects(response, '/', 302, 200)


class SignupIntegrationTestsNoLDAP(TestCase):
    def setUp(self):
        self.client = Client()

    def test_activate_no_ldap_connection_redirects_to_login(self):
        vars.QUEUEDUSER.save()
        activate_url = '/activate/%s/' % vars.QUEUEDUSER.encrypted_id
        response = self.client.get(activate_url)
        self.assertRedirects(response, '/login/', 302, 200)

    def test_activate_page_without_token_returns_404(self):
        response = self.client.get('/activate/')
        self.assertTrue(response.status_code, 404)
