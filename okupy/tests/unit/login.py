# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import User
from django.core import mail
from django.core.urlresolvers import resolve
from django.db import DatabaseError
from django.template import RequestContext

from ...accounts.views import login
from ...accounts.forms import LoginForm
from ...common.test_helpers import OkupyTestCase, set_request

import mock


account1 = {'username': 'alice', 'password': 'ldaptest'}
account2 = {'username': 'bob', 'password': 'ldapmoretest'}
wrong_account = {'username': 'wrong', 'password': 'wrong'}


class LoginUnitTests(OkupyTestCase):
    def test_login_url_resolves_to_login_view(self):
        found = resolve('/login/')
        self.assertEqual(found.func, login)

    def test_login_page_returns_200(self):
        request = set_request(uri='/login')
        response = login(request)
        self.assertEqual(response.status_code, 200)

    def test_rendered_login_form(self):
        request = set_request(uri='/login')
        response = login(request)
        login_form_part = '<input id="id_username" maxlength="100" name="username" type="text" />'
        self.assertIn(login_form_part, response.content)

    def test_empty_user_raises_form_error_messages(self):
        request = set_request(uri='/login')
        response = login(request)
        response.context = RequestContext(request, {'login_form': LoginForm(request.POST)})
        self.assertFormError(response, 'login_form', 'username', 'This field is required.')
        self.assertFormError(response, 'login_form', 'password', 'This field is required.')

    def test_empty_user_raises_login_failed(self):
        request = set_request(uri='/login', post=True, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, 'Login failed', 40)

    def test_dont_authenticate_from_db_when_ldap_is_down(self):
        request = set_request(uri='/login', post=account2, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, 'Login failed', 40)

    def test_incorrect_user_raises_login_failed(self):
        request = set_request(uri='/login', post=wrong_account, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, 'Login failed', 40)

    def test_incorrect_user_does_not_get_transferred_in_db(self):
        request = set_request(uri='/login', post=wrong_account, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertEqual(User.objects.count(), 0)

    def test_no_ldap(self):
        request = set_request(uri='/login', post=wrong_account, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, 'Login failed', 40)


class LoginUnitTestsNoDatabase(OkupyTestCase):
    cursor_wrapper = mock.Mock()
    cursor_wrapper.side_effect = DatabaseError

    @mock.patch("django.db.backends.util.CursorWrapper", cursor_wrapper)
    def test_no_database_raises_critical(self):
        request = set_request(uri='/login', post=account1, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, "Can't contact the LDAP server or the database", 40)

    @mock.patch("django.db.backends.util.CursorWrapper", cursor_wrapper)
    def test_no_database_sends_notification_mail(self):
        request = set_request(uri='/login', post=account1, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(mail.outbox[0].subject.startswith('%sERROR:' % settings.EMAIL_SUBJECT_PREFIX))
