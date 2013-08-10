# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.core.urlresolvers import resolve
from django.test import TestCase

from ...accounts.views import login, index, signup
from ...common.test_helpers import OkupyTestCase, set_request


class LoginViewTests(TestCase):
    request = set_request(uri='/login')
    response = login(request)

    def test_login_url_resolves_to_login_view(self):
        found = resolve('/login/')
        self.assertEqual(found.func, login)

    def test_login_page_returns_200(self):
        self.assertEqual(self.response.status_code, 200)

    def test_login_page_uses_correct_template(self):
        self.assertTemplateUsed('login.html')


class IndexViewTests(TestCase):
    request = set_request(uri='/')
    response = index(request)

    def test_index_url_resolves_to_index_view(self):
        found = resolve('/')
        self.assertEqual(found.func, index)

    def test_index_page_returns_302_for_anonymous(self):
        self.assertEqual(self.response.status_code, 302)


class SignupViewTests(TestCase):
    request = set_request(uri='/signup')
    response = signup(request)

    def test_signup_url_resolves_to_signup_view(self):
        found = resolve('/signup/')
        self.assertEqual(found.func, signup)

    def test_index_page_returns_200_for_anonymous(self):
        self.assertEqual(self.response.status_code, 200)

    def test_index_page_uses_correct_template(self):
        self.assertTemplateUsed('signup.html')
