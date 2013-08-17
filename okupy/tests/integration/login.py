# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test.client import Client

from mockldap import MockLdap

from ...common.test_helpers import OkupyTestCase, get_ldap_user, set_search_seed


account1 = {'username': 'alice', 'password': 'ldaptest'}
account2 = {'username': 'bob', 'password': 'ldapmoretest'}
wrong_account = {'username': 'wrong', 'password': 'wrong'}


class LoginIntegrationTests(OkupyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

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
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice')])
        account = account1.copy()
        account['next'] = ''
        response = self.client.post('/login/', account)
        self.assertRedirects(response, '/', 302, 200)

    def test_already_authenticated_user_redirects_to_index(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice')])
        self.client.post('/login/', account1)
        response = self.client.get('/login/')
        self.assertRedirects(response, '/')

    def test_logout_for_logged_in_user_redirects_to_login(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice')])
        self.client.post('/login/', account1)
        response = self.client.get('/logout/')
        self.assertRedirects(response, '/login/')

    def test_logout_for_anonymous_user_redirects_to_login(self):
        response = self.client.get('/logout/')
        self.assertRedirects(response, '/login/')
