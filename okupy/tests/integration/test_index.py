# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test.client import Client
from mockldap import MockLdap

from ...common.test_helpers import OkupyTestCase, ldap_users, set_search_seed


class IndexTests(OkupyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_redirect_to_login_for_anonymous(self):
        response = self.client.get('/')
        self.assertRedirects(response, '/login/?next=/')

    def test_index_page_uses_correct_template(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([ldap_users('alice')])
        response = self.client.post('/login/', {'username': 'alice', 'password': 'ldaptest'})
        response = self.client.get('/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'index.html')
