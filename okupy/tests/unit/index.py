# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.core.urlresolvers import resolve
from django.test import TestCase

from ...accounts.views import index
from ...common.test_helpers import set_request


class IndexUnitTests(TestCase):
    def test_index_url_resolves_to_index_view(self):
        found = resolve('/')
        self.assertEqual(found.func, index)

    def test_index_page_returns_302_for_anonymous(self):
        request = set_request(uri='/')
        response = index(request)
        self.assertEqual(response.status_code, 302)
