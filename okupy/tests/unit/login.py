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

from ...accounts.views import login, logout
from ...accounts.forms import LoginForm
from ...common.crypto import cipher
from ...common.test_helpers import OkupyTestCase, set_request, no_database, get_ldap_user, set_search_seed


account1 = {'username': 'alice', 'password': 'ldaptest'}
account2 = {'username': 'bob', 'password': 'ldapmoretest'}
wrong_account = {'username': 'wrong', 'password': 'wrong'}


class LoginUnitTests(OkupyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

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

    def test_incorrect_user_raises_login_failed(self):
        request = set_request(uri='/login', post=wrong_account, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, 'Login failed', 40)

    def test_incorrect_user_does_not_get_transferred_in_db(self):
        request = set_request(uri='/login', post=wrong_account, messages=True)
        login(request)
        self.assertEqual(User.objects.count(), 0)

    @no_database()
    @override_settings(AUTHENTICATION_BACKENDS=(
        'django_auth_ldap.backend.LDAPBackend',
        'django.contrib.auth.backends.ModelBackend'))
    def test_no_database_raises_critical(self):
        request = set_request(uri='/login', post=account1, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, "Can't contact the LDAP server or the database", 40)
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(mail.outbox[0].subject.startswith('%sERROR:' % settings.EMAIL_SUBJECT_PREFIX))

    def test_correct_user_gets_transferred_in_db(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice')])
        request = set_request(uri='/login', post=account1)
        login(request)
        self.assertEqual(User.objects.count(), 1)

    def test_authenticate_account_that_is_already_in_db(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice')])
        User.objects.create_user(username='alice')
        request = set_request(uri='/login', post=account1)
        login(request)
        self.assertEqual(User.objects.count(), 1)

    def test_secondary_password_is_added_in_login(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice')])
        request = set_request(uri='/login', post=account1)
        login(request)
        self.assertEqual(len(get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword']), 2)
        self.assertEqual(len(request.session['secondary_password']), 48)

    def test_secondary_password_is_removed_in_logout(self):
        secondary_password = Random.get_random_bytes(48)
        secondary_password_crypt = ldap_md5_crypt.encrypt(b64encode(secondary_password))
        self.ldapobject.directory[get_ldap_user('alice')[0]]['userPassword'].append(secondary_password_crypt)
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice', directory=self.ldapobject.directory)])
        alice = User(username='alice')
        request = set_request(uri='/login', post=account1, user=alice)
        request.session['secondary_password'] = cipher.encrypt(secondary_password)
        logout(request)
        self.assertEqual(len(get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword']), 1)


class LoginUnitTestsNoLDAP(OkupyTestCase):
    def test_dont_authenticate_from_db_when_ldap_is_down(self):
        request = set_request(uri='/login', post=account2, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, 'Login failed', 40)

    def test_no_ldap_connection_raises_login_failed_in_login(self):
        request = set_request(uri='/login', post=wrong_account, messages=True)
        response = login(request)
        response.context = RequestContext(request)
        self.assertMessage(response, 'Login failed', 40)

    def test_no_ldap_connection_in_logout_sends_notification_mail(self):
        alice = User(username='alice')
        request = set_request(uri='/login', post=account1, user=alice)
        request.session['secondary_password'] = 'test'
        logout(request)
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(mail.outbox[0].subject.startswith('%sERROR:' % settings.EMAIL_SUBJECT_PREFIX))
