# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase

from base64 import b64encode
from Crypto import Random
from mockldap import MockLdap
from passlib.hash import ldap_md5_crypt

from ...common.crypto import cipher
from ...common.ldap_helpers import set_secondary_password, remove_secondary_password
from ...common.test_helpers import set_request, set_search_seed, get_ldap_user


class SecondaryPassword(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mockldap = MockLdap(settings.DIRECTORY)

    def setUp(self):
        self.mockldap.start()
        self.ldapobject = self.mockldap[settings.AUTH_LDAP_SERVER_URI]

    def tearDown(self):
        self.mockldap.stop()

    def test_secondary_password_gets_added_in_session(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice')])
        alice = User.objects.create(username='alice', password='ldaptest')
        request = set_request(uri='/', user=alice)
        set_secondary_password(request, 'ldaptest')
        self.assertEqual(len(request.session['secondary_password']), 48)

    def test_secondary_password_gets_added_in_ldap(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice')])
        alice = User.objects.create(username='alice', password='ldaptest')
        request = set_request(uri='/', user=alice)
        self.assertEqual(len(get_ldap_user('alice')[1]['userPassword']), 1)
        set_secondary_password(request, 'ldaptest')
        self.assertEqual(len(get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword']), 2)

    def test_remove_leftovers_before_adding_secondary_password(self):
        leftover = ldap_md5_crypt.encrypt('leftover_password')
        self.ldapobject.directory[get_ldap_user('alice')[0]]['userPassword'].append(leftover)
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice', directory=self.ldapobject.directory)])
        alice = User.objects.create(username='alice', password='ldaptest')
        request = set_request(uri='/', user=alice)
        set_secondary_password(request, 'ldaptest')
        self.assertNotIn(leftover, get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword'])

    def test_dont_remove_primary_password_while_cleaning_leftovers(self):
        leftover = ldap_md5_crypt.encrypt('leftover_password')
        self.ldapobject.directory[get_ldap_user('alice')[0]]['userPassword'].append(leftover)
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice', directory=self.ldapobject.directory)])
        alice = User.objects.create(username='alice', password='ldaptest')
        request = set_request(uri='/', user=alice)
        set_secondary_password(request, 'ldaptest')
        self.assertTrue(ldap_md5_crypt.verify('ldaptest',get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword'][0]))

    def test_dont_remove_unknown_hashes_while_cleaning_leftovers(self):
        leftover = ldap_md5_crypt.encrypt('leftover_password')
        self.ldapobject.directory[get_ldap_user('alice')[0]]['userPassword'].append(leftover)
        leftover2 = 'plain_leftover2'
        self.ldapobject.directory[get_ldap_user('alice')[0]]['userPassword'].append(leftover2)
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice', directory=self.ldapobject.directory)])
        alice = User.objects.create(username='alice', password='ldaptest')
        request = set_request(uri='/', user=alice)
        set_secondary_password(request, 'ldaptest')
        self.assertIn(leftover2, get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword'])

    def test_session_and_ldap_secondary_passwords_match(self):
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice')])
        alice = User.objects.create(username='alice', password='ldaptest')
        request = set_request(uri='/', user=alice)
        set_secondary_password(request, 'ldaptest')
        self.assertTrue(ldap_md5_crypt.verify(b64encode(cipher.decrypt(request.session['secondary_password'], 48)), get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword'][1]))

    def test_remove_secondary_password_from_ldap(self):
        secondary_password = Random.get_random_bytes(48)
        secondary_password_crypt = ldap_md5_crypt.encrypt(b64encode(secondary_password))
        self.ldapobject.directory[get_ldap_user('alice')[0]]['userPassword'].append(secondary_password_crypt)
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice', directory=self.ldapobject.directory)])
        alice = User.objects.create(username='alice', password='ldaptest')
        request = set_request(uri='/', user=alice)
        request.session['secondary_password'] = cipher.encrypt(secondary_password)
        remove_secondary_password(request)
        self.assertNotIn(secondary_password_crypt, get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword'])

    def test_dont_remove_primary_password_while_removing_secondary_password(self):
        secondary_password = Random.get_random_bytes(48)
        secondary_password_crypt = ldap_md5_crypt.encrypt(b64encode(secondary_password))
        self.ldapobject.directory[get_ldap_user('alice')[0]]['userPassword'].append(secondary_password_crypt)
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice', directory=self.ldapobject.directory)])
        alice = User.objects.create(username='alice', password='ldaptest')
        request = set_request(uri='/', user=alice)
        request.session['secondary_password'] = cipher.encrypt(secondary_password)
        remove_secondary_password(request)
        self.assertTrue(ldap_md5_crypt.verify('ldaptest',get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword'][0]))

    def test_dont_remove_unknown_hashes_while_removing_secondary_password(self):
        secondary_password = Random.get_random_bytes(48)
        secondary_password_crypt = ldap_md5_crypt.encrypt(b64encode(secondary_password))
        self.ldapobject.directory[get_ldap_user('alice')[0]]['userPassword'].append(secondary_password_crypt)
        unknown_hash = 'unknown_hash'
        self.ldapobject.directory[get_ldap_user('alice')[0]]['userPassword'].append(unknown_hash)
        self.ldapobject.search_s.seed(settings.AUTH_LDAP_USER_BASE_DN, 2, set_search_seed('alice'))([get_ldap_user('alice', directory=self.ldapobject.directory)])
        alice = User.objects.create(username='alice', password='ldaptest')
        request = set_request(uri='/', user=alice)
        request.session['secondary_password'] = cipher.encrypt(secondary_password)
        remove_secondary_password(request)
        self.assertIn(unknown_hash, get_ldap_user('alice', directory=self.ldapobject.directory)[1]['userPassword'])
