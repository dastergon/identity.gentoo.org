# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test.client import Client
from mockldap import MockLdap

from ...common.testcase import OkupyTestCase

class IndexTests(OkupyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.client = Client()
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

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
