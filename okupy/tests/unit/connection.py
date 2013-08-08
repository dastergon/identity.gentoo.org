# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase, RequestFactory
from mockldap import MockLdap
from passlib.hash import ldap_md5_crypt

from ...common.ldap_helpers import get_ldap_connection

import edpwd
import ldap

class ConnectionTests(TestCase):
    settings.DIRECTORY[settings.AUTH_LDAP_USER_DN_TEMPLATE % {'user':
        'alice'}]['userPassword'].append(ldap_md5_crypt.encrypt('ldaptest2'))

    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_connection_options(self):
        anon_ldap_user = get_ldap_connection()
        self.assertEqual(self.ldapobject.get_option(ldap.OPT_X_TLS_DEMAND), True)
        self.assertEqual(self.ldapobject.get_option(ldap.OPT_REFERRALS), 1)

    def test_called_functions(self):
        anon_ldap_user = get_ldap_connection()
        self.assertEqual(self.ldapobject.methods_called(), ['initialize', 'set_option', 'set_option', 'start_tls_s', 'simple_bind_s'])

    def test_get_anon_user(self):
        anon_ldap_user = get_ldap_connection()
        self.assertEqual(self.ldapobject.bound_as, 'cn=anon,o=test')

    def test_get_admin_user(self):
        admin_ldap_user = get_ldap_connection(admin=True)
        self.assertEqual(self.ldapobject.bound_as, 'cn=Manager,o=test')

    def test_get_defined_user(self):
        alice = get_ldap_connection(username='alice', password='ldaptest')
        self.assertEqual(self.ldapobject.bound_as, 'uid=alice,ou=people,o=test')

    def test_many_users_defined(self):
        self.assertRaises(TypeError, get_ldap_connection, username='alice', password='ldaptest', admin=True)

    def test_get_logged_in_user(self):
        request = RequestFactory().get('/')
        request.user = User.objects.create_user(username='alice', password='ldaptest')
        request.user.secondary_password = edpwd.encrypt(settings.SECRET_KEY, 'ldaptest2')
        alice = get_ldap_connection(request=request)
        self.assertEqual(self.ldapobject.bound_as, 'uid=alice,ou=people,o=test')
