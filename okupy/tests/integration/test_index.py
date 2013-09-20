# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test import TestCase
from django.test.client import Client
from mockldap import MockLdap

from okupy.tests import vars


class IndexIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    @classmethod
    def tearDownClass(cls):
        del cls.mockldap

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobj = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()
        del self.ldapobj

    def test_redirect_to_login_for_anonymous(self):
        response = self.client.get('/')
        self.assertRedirects(response, '/login/?next=/')

    def test_index_page_uses_correct_template(self):
        response = self.client.post('/login/', vars.LOGIN_ALICE)
        response = self.client.get('/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'index.html')
