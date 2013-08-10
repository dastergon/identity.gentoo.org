# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import User
from django.test.client import Client

from mockldap import MockLdap

from ...common.test_helpers import OkupyTestCase


account1 = {'username': 'alice', 'password': 'ldaptest'}
account2 = {'username': 'bob', 'password': 'ldapmoretest'}
wrong_account = {'username': 'wrong', 'password': 'wrong'}


class LoginTestsEmptyDB(OkupyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_login_page_uses_correct_template(self):
        response = self.client.get('/login/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'login.html')

    def test_correct_user_post_login_redirect(self):
        account = account1.copy()
        account['next'] = ''
        response = self.client.post('/login/', account)
        self.assertRedirects(response, '/')
        response = self.client.get('/')
        self.assertIn('Personal Information', response.content)

    def test_correct_user_gets_transferred_in_db(self):
        response = self.client.post('/login/', account1)
        user = User.objects.get(pk=1)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(user.username, 'alice')
        self.assert_(not user.has_usable_password())
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, '')
        self.assertEqual(user.email, '')

    def test_already_authenticated_user_redirects_to_index(self):
        response = self.client.post('/login/', account1)
        response = self.client.get('/login/')
        self.assertRedirects(response, '/')

    def test_logout_for_logged_in_user_redirects_to_login(self):
        response = self.client.post('/login/', account1)
        response = self.client.get('/logout/')
        self.assertRedirects(response, '/login/')

    def test_logout_for_anonymous_user_redirects_to_login(self):
        response = self.client.get('/logout/')
        self.assertRedirects(response, '/login/')


class LoginTestsOneAccountInDB(OkupyTestCase):
    fixtures = ['alice']

    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_authenticate_account_that_is_already_in_db(self):
        response = self.client.post('/login/', account1)
        self.assertRedirects(response, '/')
        user = User.objects.get(pk=1)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(user.username, 'alice')
        self.assert_(not user.has_usable_password())
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, '')
        self.assertEqual(user.email, '')

    def test_authenticate_new_account(self):
        response = self.client.post('/login/', account2)
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
