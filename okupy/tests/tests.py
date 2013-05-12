# -*- coding: utf-8 -*-

# prepare environment
from django_auth_ldap.tests import MockLDAP
from django.conf import settings
from okupy.tests.settings import AUTH_LDAP_USER_DN_TEMPLATE

settings.AUTH_LDAP_USER_DN_TEMPLATE = AUTH_LDAP_USER_DN_TEMPLATE

alice = ("uid=alice,ou=people,o=test", {
    "uid": ["alice"],
    "userPassword": ["ldaptest"],
    "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
    "uidNumber": ["1000"],
    "gidNumber": ["1000"],
    "givenName": ["Alice"],
    "sn": ["Adams"],
})
bob = ("uid=bob,ou=people,o=test", {
    "uid": ["bob"],
    "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
    "userPassword": ["ldapmoretest"],
    "uidNumber": ["1001"],
    "gidNumber": ["50"],
    "givenName": ["Robert"],
    "sn": ["Barker"]
})
dressler = (u"uid=dreßler,ou=people,o=test".encode('utf-8'), {
    "uid": [u"dreßler".encode('utf-8')],
    "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
    "userPassword": ["password"],
    "uidNumber": ["1002"],
    "gidNumber": ["50"],
    "givenName": ["Wolfgang"],
    "sn": [u"Dreßler".encode('utf-8')]
})

_mock_ldap = MockLDAP({
    alice[0]: alice[1],
    bob[0]: bob[1],
    dressler[0]: dressler[1],
})

# run tests modules
from accounts import *
