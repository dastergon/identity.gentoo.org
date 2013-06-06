# -*- coding: utf-8 -*-

from django.conf import settings
from django_auth_ldap.config import _LDAPConfig
from django_auth_ldap.tests import MockLDAP
from django.contrib.auth.models import User
from django.core import mail
from django.test.client import Client
from okupy.accounts.models import Queue
from okupy.common.testcase import OkupyTestCase
from okupy.tests.tests import example_directory
import re

class SignupTestsEmptyDB(OkupyTestCase):
    def setUp(self):
        self.client = Client()
        self.form_data = {
            'username': 'testusername',
            'first_name': 'testfirstname',
            'last_name': 'testlastname',
            'email': 'test@test.com',
            'password_origin': 'testpassword',
            'password_verify': 'testpassword',
        }

    def test_template(self):
        response = self.client.get('/signup/')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('signup_form' in response.context)
        self.assertTrue('messages' in response.context)

    def test_empty_form(self):
        response = self.client.post('/signup/')
        self.assertFormError(response, 'signup_form', 'username', [u'This field is required.'])
        self.assertFormError(response, 'signup_form', 'first_name', [u'This field is required.'])
        self.assertFormError(response, 'signup_form', 'last_name', [u'This field is required.'])
        self.assertFormError(response, 'signup_form', 'email', [u'This field is required.'])
        self.assertFormError(response, 'signup_form', 'password_origin', [u'This field is required.'])
        self.assertFormError(response, 'signup_form', 'password_verify', [u'This field is required.'])
        self.assertEqual(Queue.objects.count(), 0)

    def test_passwords_dont_match(self):
        self.form_data['password_verify'] = 'testpassword2'
        response = self.client.post('/signup/', self.form_data)
        self.assertMessage(response, "Passwords don't match")
        self.assertEqual(Queue.objects.count(), 0)

    def test_invalid_email(self):
        self.form_data['email'] = 'test'
        response = self.client.post('/signup/', self.form_data)
        self.assertFormError(response, 'signup_form', 'email', [u'Enter a valid email address.'])
        self.assertEqual(Queue.objects.count(), 0)

class SignupTestsOneAccountInQueue(OkupyTestCase):
    fixtures = ['queued_account.json']

    def setUp(self):
        self.client = Client()
        self._mock_ldap = MockLDAP(example_directory)
        self.ldap = _LDAPConfig.ldap = self._mock_ldap
        self.queued_account = Queue.objects.get(pk=1)
        self.activate_url = '/activate/%s/' % self.queued_account.token
        self.form_data = {
            'username': 'testusername',
            'first_name': 'testfirstname',
            'last_name': 'testlastname',
            'email': 'test@test.com',
            'password_origin': 'testpassword',
            'password_verify': 'testpassword',
        }

    def tearDown(self):
        self._mock_ldap.reset()

    def test_add_queued_account_to_ldap(self):
        response = self.client.get(self.activate_url)
        self.assertRedirects(response, '/login/')
        self.assertMessage(response, 'Your account has been activated successfully')
        self.assertEqual(Queue.objects.count(), 0)
        ldap_account = self._mock_ldap.directory['uid=%s,ou=people,o=test' % self.queued_account.username]
        self.assertEqual(ldap_account['uid'][0], self.queued_account.username)
        self.assertEqual(ldap_account['givenName'][0], self.queued_account.first_name)
        self.assertEqual(ldap_account['sn'][0], self.queued_account.last_name)
        self.assertEqual(ldap_account['objectClass'], settings.AUTH_LDAP_USER_OBJECTCLASS)
        self.assertEqual(ldap_account['uidNumber'][0], '1003')
        self.assertEqual(ldap_account['mail'][0], self.queued_account.email)
        data={'username': self.queued_account.username, 'password': 'queuedpass'}
        response = self.client.post('/login/', data)
        self.assertRedirects(response, '/')
        self.assertEqual(User.objects.count(), 1)
        response = self.client.get(self.activate_url)
        self.assertMessage(response, 'Invalid URL')

    def test_signup_no_ldap(self):
        _LDAPConfig.ldap = None
        response = self.client.post('/signup/', self.form_data)
        self.assertMessage(response, "Can't contact LDAP server")
        self.assertEqual(Queue.objects.count(), 1)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, '%sERROR: {\'desc\': "Can\'t contact LDAP server"}' % settings.EMAIL_SUBJECT_PREFIX)

    def test_activate_no_ldap(self):
        _LDAPConfig.ldap = None
        response = self.client.get(self.activate_url)
        self.assertRedirects(response, '/login/')
        self.assertMessage(response, "Can't contact LDAP server")
        self.assertEqual(Queue.objects.count(), 1)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, '%sERROR: {\'desc\': "Can\'t contact LDAP server"}' % settings.EMAIL_SUBJECT_PREFIX)

    def test_wrong_activation_link(self):
        response = self.client.get('/activate/invalidurl/')
        self.assertRedirects(response, '/login/')
        self.assertMessage(response, 'Invalid URL')
        self.assertEqual(Queue.objects.count(), 1)

    def test_username_already_exists_in_ldap(self):
        self.form_data['username'] = 'alice'
        response = self.client.post('/signup/', self.form_data)
        self.assertMessage(response, 'Username already exists')

    def test_email_already_exists_in_ldap(self):
        self.form_data['email'] = 'alice@test.com'
        response = self.client.post('/signup/', self.form_data)
        self.assertMessage(response, 'Email already exists')

    def test_username_already_pending_activation(self):
        self.form_data['username'] = 'queueduser'
        response = self.client.post('/signup/', self.form_data)
        self.assertMessage(response, 'Account is already pending activation')
        self.assertEqual(Queue.objects.count(), 1)

    def test_email_already_pending_activation(self):
        self.form_data['email'] = 'queueduser@test.com'
        response = self.client.post('/signup/', self.form_data)
        self.assertMessage(response, 'Account is already pending activation')
        self.assertEqual(Queue.objects.count(), 1)

    def test_valid_data_to_form(self):
        response = self.client.post('/signup/', self.form_data)
        self.assertRedirects(response, '/login/')
        self.assertMessage(response, 'You will shortly receive an activation mail')
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, '%sAccount Activation' % settings.EMAIL_SUBJECT_PREFIX)
        self.assertEqual(Queue.objects.count(), 2)
        queued_account = Queue.objects.get(pk=2)
        self.assertEqual(queued_account.username, self.form_data['username'])
        self.assertEqual(queued_account.first_name, self.form_data['first_name'])
        self.assertEqual(queued_account.last_name, self.form_data['last_name'])
        self.assertEqual(queued_account.email, self.form_data['email'])
        self.assertEqual(queued_account.password, self.form_data['password_origin'])
        self.assertEqual(len(queued_account.token), 40)
        valid_token = re.compile(r'\w+')
        self.assertTrue(valid_token.match(queued_account.token))
