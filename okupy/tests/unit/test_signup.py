# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.core.urlresolvers import resolve
from django.test import TestCase

from ...accounts.views import signup
from ...common.test_helpers import set_request


class SignupUnitTests(TestCase):
    def test_signup_url_resolves_to_signup_view(self):
        found = resolve('/signup')
        self.assertEqual(found.func, signup)

    def test_signup_page_returns_200_for_anonymous(self):
        request = set_request(uri='/signup')
        response = signup(request)
        self.assertEqual(response.status_code, 200)
