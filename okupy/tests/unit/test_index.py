# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.core.urlresolvers import resolve
from django.test import TestCase

from mockldap import MockLdap

from okupy.accounts.views import index
from okupy.common.test_helpers import set_request
from okupy.tests import vars


class IndexUnitTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    def setUp(self):
        self.mockldap.start()
        self.ldapobj = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()
        del self.ldapobj

    def test_index_url_resolves_to_index_view(self):
        found = resolve('/')
        self.assertEqual(found.func, index)

    def test_index_page_returns_200_for_logged_in(self):
        request = set_request(uri='/', user=vars.USER_ALICE)
        response = index(request)
        self.assertEqual(response.status_code, 200)

    def test_rendered_index_page(self):
        request = set_request(uri='/', user=vars.USER_ALICE)
        response = index(request)
        nickname_html = '<tr class="even"><th>Nickname</th><td>alice</td></tr>'
        self.assertIn(nickname_html, response.content)
