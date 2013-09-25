# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import User
from django.core import mail
from django.core.urlresolvers import resolve
from django.template import RequestContext
from django.test.utils import override_settings

from base64 import b64encode
from Crypto import Random
from passlib.hash import ldap_md5_crypt
from mockldap import MockLdap

from okupy.accounts.views import login, logout
from okupy.accounts.forms import LoginForm
from okupy.common.test_helpers import (OkupyTestCase, set_request, no_database,
                                       ldap_users)
from okupy.crypto.ciphers import cipher
from okupy.tests import vars


class LoginUnitTests(OkupyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    @classmethod
    def tearDownClass(cls):
        del cls.mockldap

    def setUp(self):
        self.mockldap.start()
        self.ldapobj = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()
        del self.ldapobj

    def test_incorrect_user_raises_login_failed(self):
        request = set_request(uri='/login', post=vars.LOGIN_WRONG,
                              messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, 'Login failed', 40)

    def test_incorrect_user_does_not_get_transferred_in_db(self):
        request = set_request(uri='/login', post=vars.LOGIN_WRONG,
                              messages=True)
        login(request)
        self.assertEqual(User.objects.count(), 0)

    @no_database()
    @override_settings(AUTHENTICATION_BACKENDS=(
        'okupy.common.auth.LDAPAuthBackend',
        'django.contrib.auth.backends.ModelBackend'))
    def test_no_database_raises_critical(self):
        request = set_request(uri='/login', post=vars.LOGIN_ALICE,
                              messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response,
                           "Can't contact the LDAP server or the database", 40)

    @no_database()
    @override_settings(AUTHENTICATION_BACKENDS=(
        'okupy.common.auth.LDAPAuthBackend',
        'django.contrib.auth.backends.ModelBackend'))
    def test_no_database_sends_notification_mail(self):
        request = set_request(uri='/login', post=vars.LOGIN_ALICE,
                              messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(mail.outbox[0].subject.startswith('%sERROR:' %
                        settings.EMAIL_SUBJECT_PREFIX))

    def test_correct_user_gets_transferred_in_db(self):
        request = set_request(uri='/login', post=vars.LOGIN_ALICE)
        login(request)
        self.assertEqual(User.objects.count(), 1)

    def test_authenticate_account_that_is_already_in_db(self):
        vars.USER_ALICE.save()
        request = set_request(uri='/login', post=vars.LOGIN_ALICE)
        login(request)
        self.assertEqual(User.objects.count(), 1)

    def test_secondary_password_is_added_in_login(self):
        request = set_request(uri='/login', post=vars.LOGIN_ALICE)
        login(request)
        self.assertEqual(len(ldap_users(
            'alice',
            directory=self.ldapobj.directory)[1]['userPassword']), 2)
        self.assertEqual(len(request.session['secondary_password']), 48)

    def test_secondary_password_is_removed_in_logout(self):
        secondary_password = Random.get_random_bytes(48)
        secondary_password_crypt = ldap_md5_crypt.encrypt(b64encode(
            secondary_password))
        self.ldapobj.directory[ldap_users('alice')[0]][
            'userPassword'].append(secondary_password_crypt)
        request = set_request(uri='/login', post=vars.LOGIN_ALICE,
                              user=vars.USER_ALICE)
        request.session['secondary_password'] = cipher.encrypt(
            secondary_password)
        logout(request)
        self.assertEqual(len(ldap_users(
            'alice',
            directory=self.ldapobj.directory)[1]['userPassword']), 1)


class LoginUnitTestsNoLDAP(OkupyTestCase):
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
        login_form_part = '<input id="id_username" maxlength="100"'
        'name="username" type="text" />'
        self.assertIn(login_form_part, response.content)

    def test_empty_user_raises_form_error_messages(self):
        request = set_request(uri='/login')
        response = login(request)
        response.context = RequestContext(request, {
            'login_form': LoginForm(request.POST)})
        self.assertFormError(response, 'login_form', 'username',
                             'This field is required.')
        self.assertFormError(response, 'login_form', 'password',
                             'This field is required.')

    def test_empty_user_raises_login_failed(self):
        request = set_request(uri='/login', post=True, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, 'Login failed', 40)

    def test_dont_authenticate_from_db_when_ldap_is_down(self):
        request = set_request(uri='/login', post=vars.LOGIN_BOB,
                              messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response,
                           "Can't contact the LDAP server or the database", 40)

    def test_no_ldap_connection_raises_ldaperror_in_login(self):
        request = set_request(uri='/login', post=vars.LOGIN_WRONG,
                              messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response,
                           "Can't contact the LDAP server or the database", 40)

    def test_no_ldap_connection_in_logout_sends_notification_mail(self):
        request = set_request(uri='/login', post=vars.LOGIN_ALICE,
                              user=vars.USER_ALICE)
        request.session['secondary_password'] = 'test'
        logout(request)
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(mail.outbox[0].subject.startswith('%sERROR:' %
                        settings.EMAIL_SUBJECT_PREFIX))
