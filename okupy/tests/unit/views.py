# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.core.urlresolvers import resolve
from django.test import TestCase

from ...accounts.views import login, index, signup
from ...common.test_helpers import OkupyTestCase, set_request


account1 = {'username': 'alice', 'password': 'ldaptest'}
account2 = {'username': 'bob', 'password': 'ldapmoretest'}
wrong_account = {'username': 'wrong', 'password': 'wrong'}


class LoginViewTests(TestCase):
    def test_login_url_resolves_to_login_view(self):
        found = resolve('/login/')
        self.assertEqual(found.func, login)

    def test_login_page_returns_200(self):
        request = set_request(uri='/login')
        response = login(request)
        self.assertEqual(response.status_code, 200)


class IndexViewTests(TestCase):
    def test_index_url_resolves_to_index_view(self):
        found = resolve('/')
        self.assertEqual(found.func, index)

    def test_index_page_returns_302_for_anonymous(self):
        request = set_request(uri='/')
        response = index(request)
        self.assertEqual(response.status_code, 302)


class SignupViewTests(TestCase):
    def test_signup_url_resolves_to_signup_view(self):
        found = resolve('/signup/')
        self.assertEqual(found.func, signup)

    def test_index_page_returns_200_for_anonymous(self):
        request = set_request(uri='/signup')
        response = signup(request)
        self.assertEqual(response.status_code, 200)
