# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import User
from django.core import mail
from django.db import DatabaseError
from django.test.client import Client
from mockldap import MockLdap

from ...common.testcase import OkupyTestCase

import mock

class LoginTestsEmptyDB(OkupyTestCase):
    cursor_wrapper = mock.Mock()
    cursor_wrapper.side_effect = DatabaseError
    account = {'username': 'alice', 'password': 'ldaptest'}

    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_template(self):
        response = self.client.get('/login/')
        self.assertIn('login_form', response.context)
        self.assertIn('messages', response.context)

    def test_empty_user(self):
        response = self.client.post('/login/')
        self.assertFormError(response, 'login_form', 'username', [u'This field is required.'])
        self.assertFormError(response, 'login_form', 'password', [u'This field is required.'])
        self.assertMessage(response, 'Login failed', 40)
        self.assertEqual(User.objects.count(), 0)

    def test_correct_user_leading_space_in_username(self):
        account = self.account.copy()
        account['username'] = ' %s' % self.account['username']
        response = self.client.post('/login/', account)
        self.assertRedirects(response, '/')
        user = User.objects.get(pk=1)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(user.username, 'alice')
        self.assert_(not user.has_usable_password())

    def test_correct_user_trailing_space_in_username(self):
        account = self.account.copy()
        account['username'] = '%s ' % self.account['username']
        response = self.client.post('/login/', account)
        self.assertRedirects(response, '/')
        user = User.objects.get(pk=1)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(user.username, 'alice')
        self.assert_(not user.has_usable_password())

    def test_incorrect_user(self):
        wrong_account = {'username': 'username', 'password': 'password'}
        response = self.client.post('/login/', wrong_account)
        self.assertMessage(response, 'Login failed', 40)
        self.assertEqual(User.objects.count(), 0)

    def test_correct_user(self):
        account = self.account.copy()
        account['next'] = ''
        response = self.client.post('/login/', account)
        self.assertRedirects(response, '/')
        user = User.objects.get(pk=1)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(user.username, 'alice')
        self.assert_(not user.has_usable_password())
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, '')
        self.assertEqual(user.email, '')

    def test_no_ldap(self):
        self.mockldap.stop()
        response = self.client.post('/login/', self.account)
        self.assertMessage(response, 'Login failed', 40)
        self.assertEqual(User.objects.count(), 0)
        self.mockldap.start()

    @mock.patch("django.db.backends.util.CursorWrapper", cursor_wrapper)
    def test_no_database(self):
        response = self.client.post('/login/', self.account)
        self.assertMessage(response, "Can't contact the LDAP server or the database", 40)
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(mail.outbox[0].subject.startswith('%sERROR:' % settings.EMAIL_SUBJECT_PREFIX))

    def test_already_authenticated_user_redirects_to_index(self):
        response = self.client.post('/login/', self.account)
        response = self.client.get('/login/')
        self.assertRedirects(response, '/')

    def test_logout_for_logged_in_user(self):
        response = self.client.post('/login/', self.account)
        response = self.client.get('/logout/')
        self.assertRedirects(response, '/login/')

    def test_logout_for_anonymous_user(self):
        response = self.client.get('/logout/')
        self.assertRedirects(response, '/login/')

class LoginTestsOneAccountInDB(OkupyTestCase):
    fixtures = ['alice']

    account1 = {'username': 'alice', 'password': 'ldaptest'}
    account2 = {'username': 'bob', 'password': 'ldapmoretest'}

    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_dont_authenticate_from_db_when_ldap_is_down(self):
        self.mockldap.stop()
        response = self.client.post('/login/', self.account1)
        self.assertMessage(response, 'Login failed', 40)
        self.assertEqual(User.objects.count(), 1)
        self.mockldap.start()

    def test_authenticate_account_that_is_already_in_db(self):
        response = self.client.post('/login/', self.account1)
        self.assertRedirects(response, '/')
        user = User.objects.get(pk=1)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(user.username, 'alice')
        self.assert_(not user.has_usable_password())
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, '')
        self.assertEqual(user.email, '')

    def test_authenticate_new_account(self):
        response = self.client.post('/login/', self.account2)
        self.assertRedirects(response, '/')
        self.assertEqual(User.objects.count(), 2)
        user1 = User.objects.get(pk=1)
        self.assertEqual(user1.username, 'alice')
        self.assert_(not user1.has_usable_password())
        self.assertEqual(user1.first_name, '')
        self.assertEqual(user1.last_name, '')
        self.assertEqual(user1.email, '')
        user2 = User.objects.get(pk=2)
        self.assertEqual(user2.username, 'bob')
        self.assert_(not user2.has_usable_password())
        self.assertEqual(user2.first_name, '')
        self.assertEqual(user2.last_name, '')
        self.assertEqual(user2.email, '')
