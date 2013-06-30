# -*- coding: utf-8 -*-

from django.contrib.auth.models import AnonymousUser
from django.core.urlresolvers import resolve
from django.http import HttpRequest
from django.template.loader import render_to_string
from django.test import TestCase
from okupy.accounts.views import login

class LoginTests(TestCase):
    def test_login_url_resolves_to_login_view(self):
        found = resolve('/login/')
        self.assertEqual(found.func, login)

    def test_login_page_returns_correct_html(self):
        request = HttpRequest()
        request.user = AnonymousUser()
        response = login(request)
        expected_html = render_to_string('login.html')
        self.assertEqual(response.content, expected_html)

    def test_login_can_save_a_POST_request(self):
        request = HttpRequest()
        request.method = 'POST'
        request.POST['item_text'] = 'A new list item'
        response = login(request)
        self.assertIn('A new list item', response.content)
