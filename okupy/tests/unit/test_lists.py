# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.core.urlresolvers import resolve

from mockldap import MockLdap

from okupy.accounts.views import lists
from okupy.common.test_helpers import OkupyTestCase, set_request
from okupy.tests import vars


class ListsUnitTests(OkupyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    def setUp(self):
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_devlist_url_resolves_to_lists_view(self):
        found = resolve('/devlist/')
        self.assertEqual(found.func, lists)

    def test_devlist_page_returns_200(self):
        request = set_request(uri='/devlist')
        response = lists(request, 'devlist')
        self.assertEqual(response.status_code, 200)

    def test_rendered_devlist_page(self):
        request = set_request(uri='/devlist')
        response = lists(request, 'devlist')
        page_part = '<tr>\n                    <td class="devname"><b>alice</b></td>\n                    <td>Alice Adams</td>\n                    <td><a href="http://maps.google.com/maps?q=City1, Country1">City1, Country1</a></td>\n                    <td class="tableinfo">kde, qt, cluster</td>\n                </tr>'  # noqa
        self.assertIn(page_part, response.content)

    def test_former_devlist_url_resolves_to_lists_view(self):
        found = resolve('/former-devlist/')
        self.assertEqual(found.func, lists)

    def test_former_devlist_page_returns_200(self):
        request = set_request(uri='/former-devlist')
        response = lists(request, 'former-devlist')
        self.assertEqual(response.status_code, 200)

    def test_rendered_former_devlist_page(self):
        request = set_request(uri='/former-devlist')
        response = lists(request, 'former-devlist')
        page_part = '<tr>\n                    <td class="devname"><b>john</b></td>\n                    <td>John Smith</td>\n                    <td><a href="http://maps.google.com/maps?q=City3, Country3">City3, Country3</a></td>\n                    <td class="tableinfo">kernel, security</td>\n                </tr>'  # noqa
        self.assertIn(page_part, response.content)

    def test_foundation_members_list_url_resolves_to_lists_view(self):
        found = resolve('/foundation-members/')
        self.assertEqual(found.func, lists)

    def test_foundation_members_page_returns_200(self):
        request = set_request(uri='/foundation-members')
        response = lists(request, 'foundation-members')
        self.assertEqual(response.status_code, 200)

    def test_rendered_foundation_members_page(self):
        request = set_request(uri='/foundation-members')
        response = lists(request, 'foundation-members')
        page_part = '<tr>\n                <td style="color:#5c4f85;"><b>bob</b></td>\n                <td>Robert Barker</td>\n                <td><a href="http://maps.google.com/maps?q=City2, Country2">City2, Country2</a></td>\n            </tr>'  # noqa
        page_part = '<tr>\n                    <td style="color:#5c4f85;"><b>bob</b></td>\n                    <td>Robert Barker</td>\n                    <td><a href="http://maps.google.com/maps?q=City2, Country2">City2, Country2</a></td>\n                </tr>'  # noqa
        self.assertIn(page_part, response.content)
