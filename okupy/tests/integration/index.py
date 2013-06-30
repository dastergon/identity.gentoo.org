# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.test.client import Client
from django_auth_ldap.config import _LDAPConfig
from django_auth_ldap.tests import MockLDAP

from ...common.testcase import OkupyTestCase
from ..tests import example_directory

class IndexTests(OkupyTestCase):
    def setUp(self):
        self.client = Client()
        self._mock_ldap = MockLDAP(example_directory)
        self.ldap = _LDAPConfig.ldap = self._mock_ldap

    def tearDown(self):
        self._mock_ldap.reset()

    def test_redirect_to_login_for_anonymous(self):
        response = self.client.get('/')
        self.assertRedirects(response, '/login/?next=/')
        self.assertTemplateUsed('login.html')

    def test_template(self):
        response = self.client.post('/login/', {'username': 'alice', 'password': 'ldaptest'})
        self.assertRedirects(response, '/')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed('index.html')
