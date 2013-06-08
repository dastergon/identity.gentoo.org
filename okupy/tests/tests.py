# -*- coding: utf-8 -*-

example_directory = {
    "uid=alice,ou=people,o=test": {
        "uid": ["alice"],
        "userPassword": ['{CRYPT}$1$lO/RU6zz$2fJCOwurxBtCqdImkoLQo1'],
        "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
        "uidNumber": ["1000"],
        "gidNumber": ["1000"],
        "givenName": ["Alice"],
        "sn": ["Adams"],
        "mail": ["alice@test.com"],
    },
    "uid=bob,ou=people,o=test": {
        "uid": ["bob"],
        "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
        "userPassword": ['{CRYPT}$1$eFSQMJY6$8y.WUL/ONeEarVXqeCIbH.'],
        "uidNumber": ["1001"],
        "gidNumber": ["50"],
        "givenName": ["Robert"],
        "sn": ["Barker"],
        "mail": ["bob@test.com"],
    },
    u"uid=dreßler,ou=people,o=test".encode('utf-8'): {
        "uid": [u"dreßler".encode('utf-8')],
        "objectClass": ["person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
        "userPassword": ['{CRYPT}$1$kQ3GmP3k$oKSdmDpdepvrni/JQQ4Ri.'],
        "uidNumber": ["1002"],
        "gidNumber": ["50"],
        "givenName": ["Wolfgang"],
        "sn": [u"Dreßler".encode('utf-8')],
        "mail": ["dressler@test.com"],
    }
}

# run tests modules
from integration.login import *
from integration.signup import *
