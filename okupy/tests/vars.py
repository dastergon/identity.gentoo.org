# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

""" Various variables used by the tests """

from django.conf import settings
from django.contrib.auth.models import User

from ..accounts.models import Queue


# LDAP directory
DIRECTORY = {
    "o=test": {},
    "cn=anon,o=test": {
        "userPassword": ["{CRYPT}$1$n4jlXi20$.5a8UTvwIqVfVAMlXJ1EZ0"],
    },
    "cn=Manager,o=test": {
        "userPassword": ["{CRYPT}$1$sY4mlRve$0eg5TLYMyZfBCIUgU/RPf0"],
    },
    "ou=people,o=test": {},
    "uid=alice,ou=people,o=test": {
        "uid": ["alice"],
        "userPassword": ['{CRYPT}$1$lO/RU6zz$2fJCOwurxBtCqdImkoLQo1'],
        "objectClass": settings.AUTH_LDAP_USER_OBJECTCLASS +
        settings.AUTH_LDAP_DEV_OBJECTCLASS,
        "uidNumber": ["1000"],
        "gidNumber": ["1000"],
        "givenName": ["Alice"],
        "sn": ["Adams"],
        "cn": ["Alice Adams"],
        "mail": ["alice@test.com"],
        "gentooRoles": ["kde, qt, cluster"],
        "gentooLocation": ["City1, Country1"],
        "gentooACL": ["user.group", "developer.group"],
    },
    "uid=bob,ou=people,o=test": {
        "uid": ["bob"],
        "userPassword": ['{CRYPT}$1$eFSQMJY6$8y.WUL/ONeEarVXqeCIbH.'],
        "objectClass": settings.AUTH_LDAP_USER_OBJECTCLASS,
        "uidNumber": ["1001"],
        "gidNumber": ["50"],
        "givenName": ["Robert"],
        "sn": ["Barker"],
        "cn": ["Robert Barker"],
        "mail": ["bob@test.com"],
        "gentoRoles": ["nothing"],
        "gentooLocation": ["City2, Country2"],
        "gentooACL": ["user.group", "foundation.group"]
    },
    "uid=jack,ou=people,o=test": {
        "uid": ["jack"],
        "objectClass": settings.AUTH_LDAP_USER_OBJECTCLASS +
        settings.AUTH_LDAP_DEV_OBJECTCLASS,
        "gentooACL": ["user.group", "developer.group", "foundation.group"],
    },
    "uid=john,ou=people,o=test": {
        "uid": ["john"],
        "objectClass": settings.AUTH_LDAP_USER_OBJECTCLASS,
        "cn": ["John Smith"],
        "gentooLocation": ["City3, Country3"],
        "gentooRoles": ["kernel, security"],
        "gentooACL": ["user.group", "retired.group"],
    },
    "uid=matt,ou=people,o=test": {
        "objectClass": settings.AUTH_LDAP_USER_OBJECTCLASS,
        "gentooACL": ["user.group", "retired.group"],
    },
}

# User objects
USER_ALICE = User(username='alice', password='ldaptest')

# Queue objects
QUEUEDUSER = Queue(
    username='queueduser',
    password='queuedpass',
    email='queued_user@test.com',
    first_name='queued_first_name',
    last_name='queued_last_name',
)

# login form data
LOGIN_ALICE = {'username': 'alice', 'password': 'ldaptest'}
LOGIN_BOB = {'username': 'bob', 'password': 'ldapmoretest'}
LOGIN_WRONG = {'username': 'wrong', 'password': 'wrong'}

# signup form data
SIGNUP_TESTUSER = {
    'username': 'testuser',
    'first_name': 'testfirstname',
    'last_name': 'testlastname',
    'email': 'test@test.com',
    'password_origin': 'testpassword',
    'password_verify': 'testpassword',
}

# SSL certificates

TEST_CERTIFICATE = '''-----BEGIN CERTIFICATE-----
MIICmzCCAiWgAwIBAgIBATANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJFWDEQ
MA4GA1UECAwHRXhhbXBsZTEQMA4GA1UEBwwHRXhhbXBsZTEQMA4GA1UECgwHRXhh
bXBsZTEUMBIGA1UEAwwLZXhhbXBsZS5jb20xIjAgBgkqhkiG9w0BCQEWE2V4YW1w
bGVAZXhhbXBsZS5jb20wIBcNMTMwODIyMTgzMjIyWhgPMjExMjAzMTYxODMyMjJa
MHAxCzAJBgNVBAYTAkVYMRAwDgYDVQQIDAdFeGFtcGxlMRAwDgYDVQQKDAdFeGFt
cGxlMR4wHAYDVQQDDBVFeGFtcGx1cyBFeGFtcGxpZmljdXMxHTAbBgkqhkiG9w0B
CQEWDmFsaWNlQHRlc3QuY29tMHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAKUQ3vP0
im6+perWzGyjCR59IybPVL55ZdoI3z9vIkhjNW3tvts8j3b94DxMs2W1cpTrT/bF
Ufof6miRAl1IG6LhITuWh0/3e2WPQZjgL/hWDjNnO2ssa5pFBDC90UlmqQIDAQAB
o3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRl
ZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUINRMT6uaia+DuzD0UizZwmr6ewkwHwYD
VR0jBBgwFoAUF8OTfUF4T4McbqiA4uruxlKCanUwDQYJKoZIhvcNAQEFBQADYQCJ
kSBK5nabnbmeFs53szVk7KemFq+Ew8BdVqjejSdbTB2wsGM+IknlmYOnqfLn1osW
HBbiw3zv4xb9ahmA68ChbeEyJXj6WKExD4WpAT1sDDAwlqA0fo0KSY/3E0zocs4=
-----END CERTIFICATE-----'''

TEST_CERTIFICATE_WRONG_EMAIL = '''-----BEGIN CERTIFICATE-----
MIICkzCCAh2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJFWDEQ
MA4GA1UECAwHRXhhbXBsZTEQMA4GA1UEBwwHRXhhbXBsZTEQMA4GA1UECgwHRXhh
bXBsZTEUMBIGA1UEAwwLZXhhbXBsZS5jb20xIjAgBgkqhkiG9w0BCQEWE2V4YW1w
bGVAZXhhbXBsZS5jb20wIBcNMTMwODIyMTg0ODEzWhgPMjExMjAzMTYxODQ4MTNa
MGgxCzAJBgNVBAYTAkVYMRAwDgYDVQQIDAdFeGFtcGxlMRAwDgYDVQQKDAdFeGFt
cGxlMRYwFAYDVQQDDA1Xcm9uZyBFYQhtYWlsMR0wGwYJKoZIhvcNAQkBFg53cm9u
Z0B0ZXN0LmNvbTB8MA0GCSqGSIb3DQEBAQUAA2sAMGgCYQClEN7z9IpuvqXq1sxs
owkefSMmz1S+eWXaCN8/byJIYzVt7b7bPI92/eA8TLNltXKU60/2xVH6H+pokQJd
SBui4SE7lodP93tlj0GY4C/4Vg4zZztrLGuaRQQwvdFJZqkCAwEAAaN7MHkwCQYD
VR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlm
aWNhdGUwHQYDVR0OBBYEFCDUTE+rmomvg7sw9FIs2cJq+nsJMB8GA1UdIwQYMBaA
FBfDk31BeE+DHG6ogOLq7sZSgmp1MA0GCSqGSIb3DQEBBQUAA2EAWjm5DIIpuE6e
v8NFzLjLUTJroCCMxkkCZ/9qRBFIhdHSIjH+m2vgVEfQH3ub44ncVY58WWm/A3xL
0Va/G/jNXbKVQYiUS12/BF917HDZoYmW2nbyVLXMqcbxu5gIln6C
-----END CERTIFICATE-----'''

TEST_CERTIFICATE_WITH_TWO_EMAIL_ADDRESSES = '''-----BEGIN CERTIFICATE-----
MIICsTCCAjugAwIBAgIBAzANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJFWDEQ
MA4GA1UECAwHRXhhbXBsZTEQMA4GA1UEBwwHRXhhbXBsZTEQMA4GA1UECgwHRXhh
bXBsZTEUMBIGA1UEAwwLZXhhbXBsZS5jb20xIjAgBgkqhkiG9w0BCQEWE2V4YW1w
bGVAZXhhbXBsZS5jb20wIBcNMTMwODIyMTkwMjUwWhgPMjExMjAzMTYxOTAyNTBa
MIGFMQswCQYDVQQGEwJFWDEQMA4GA1UECAwHRXhhbXBsZTEQMA4GA1UECgwHRXhh
bXBsZTEVMBMGA1UEAwwMU29tZW9uZSBFbHNlMRwwGgYJKoZIhvcNAQkBFg10ZXN0
QHRlc3QuY29tMR0wGwYJKoZIhvcNAQkBFg5hbGljZUB0ZXN0LmNvbTB8MA0GCSqG
SIb3DQEBAQUAA2sAMGgCYQClEN7z9IpuvqXq1sxsowkefSMmz1S+eWXaCN8/byJI
YzVt7b7bPI92/eA8TLNltXKU60/2xVH6H+pokQJdSBui4SE7lodP93tlj0GY4C/4
Vg4zZztrLGuaRQQwvdFJZqkCAwEAAaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhC
AQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFCDU
TE+rmomvg7sw9FIs2cJq+nsJMB8GA1UdIwQYMBaAFBfDk31BeE+DHG6ogOLq7sZS
gmp1MA0GCSqGSIb3DQEBBQUAA2EAH+Qaz/Dmd5QqU1pVgPUz2loWQhy+cX6bgubJ
vj3k/SSqj6qjnxryY6QSKWOTRbKhwmRHrrsFRuR2rCZWYZUJ6ohCDYrwVKvs7i2R
VNG3Q7+oqLajmyDfZmHkENQ0rCdc
-----END CERTIFICATE-----'''
