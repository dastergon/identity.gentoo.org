# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.core.urlresolvers import resolve
from django.test import TestCase, RequestFactory

from django_otp.middleware import OTPMiddleware

from ...accounts.views import login, index, signup
from ...accounts.forms import LoginForm

def anon_request(uri):
    request = RequestFactory().get(uri)
    request.session = {}
    request.user = AnonymousUser()
    OTPMiddleware().process_request(request)
    return request

class LoginViewTests(TestCase):
    request = anon_request('/login')
    response = login(request)

    def test_login_url_resolves_to_login_view(self):
        found = resolve('/login/')
        self.assertEqual(found.func, login)

    def test_login_page_returns_200(self):
        self.assertEqual(self.response.status_code, 200)

    def test_login_page_uses_correct_template(self):
        self.assertTemplateUsed('login.html')

class IndexViewTests(TestCase):
    request = anon_request('/')
    response = index(request)

    def test_index_url_resolves_to_index_view(self):
        found = resolve('/')
        self.assertEqual(found.func, index)

    def test_index_page_returns_302_for_anonymous(self):
        self.assertEqual(self.response.status_code, 302)

    def test_index_page_uses_correct_template(self):
        self.assertTemplateUsed('index.html')

class SignupViewTests(TestCase):
    request = anon_request('/signup')
    response = signup(request)

    def test_signup_url_resolves_to_signup_view(self):
        found = resolve('/signup/')
        self.assertEqual(found.func, signup)

    def test_index_page_returns_200_for_anonymous(self):
        self.assertEqual(self.response.status_code, 200)

    def test_index_page_uses_correct_template(self):
        self.assertTemplateUsed('signup.html')
