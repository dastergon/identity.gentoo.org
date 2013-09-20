# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test import TestCase
from django.test.client import Client

from mockldap import MockLdap

from okupy.tests import vars


class ListsIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(vars.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobj = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_devlist_page_uses_correct_template(self):
        response = self.client.get('/devlist/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'devlist.html')

    def test_former_devlist_page_uses_correct_template(self):
        response = self.client.get('/former-devlist/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'former-devlist.html')

    def test_foundation_members_page_uses_correct_template(self):
        response = self.client.get('/foundation-members/')
        self.assertTemplateUsed(response, 'base.html')
        self.assertTemplateUsed(response, 'foundation-members.html')
