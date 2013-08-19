# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import User
from django.core.urlresolvers import resolve
from django.test import TestCase

from mockldap import MockLdap

from ...accounts.views import index
from ...common.test_helpers import set_request, ldap_users, set_search_seed


alice = User(username='alice', password='ldaptest')
account2 = {'username': 'bob', 'password': 'ldapmoretest'}
wrong_account = {'username': 'wrong', 'password': 'wrong'}


class IndexUnitTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_index_url_resolves_to_index_view(self):
        found = resolve('/')
        self.assertEqual(found.func, index)

    def test_index_page_returns_200_for_logged_in(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([ldap_users('alice')])
        request = set_request(uri='/', user=alice)
        response = index(request)
        self.assertEqual(response.status_code, 200)

    def test_rendered_index_page(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([ldap_users('alice')])
        request = set_request(uri='/', user=alice)
        response = index(request)
        nickname_html = '<tr class="even"><th>Nickname</th><td>alice</td></tr>'
        self.assertIn(nickname_html, response.content)
