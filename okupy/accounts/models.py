# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.db import models
from ldapdb.models.fields import CharField, IntegerField, ListField
import ldapdb.models


class Queue(models.Model):
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=30)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=254, unique=True)
    token = models.CharField(max_length=40)


class LDAPUser(ldapdb.models.Model):
    """ Class representing an LDAP user entry """
    # LDAP metadata
    base_dn = settings.AUTH_LDAP_USER_BASE_DN
    object_classes = settings.AUTH_LDAP_USER_OBJECTCLASS + \
        settings.AUTH_LDAP_DEV_OBJECTCLASS
    # person
    last_name = CharField(db_column='sn')
    full_name = CharField(db_column='cn')
    description = CharField(db_column='description')
    phone = CharField(db_column='telephoneNumber', blank=True)
    password = ListField(db_column='userPassword')
    # inetOrgPerson
    first_name = CharField(db_column='givenName')
    email = ListField(db_column='mail')
    username = CharField(db_column='uid', primary_key=True)
    # posixAccount
    uid = IntegerField(db_column='uidNumber', unique=True)
    gid = IntegerField(db_column='gidNumber')
    gecos = CharField(db_column='gecos')
    home_directory = CharField(db_column='homeDirectory')
    login_shell = CharField(db_column='loginShell', default='/bin/bash')
    # ldapPublicKey
    ssh_key = ListField(db_column='sshPublicKey')
    # gentooGroup
    ACL = ListField(db_column='gentooACL')
    birthday = CharField(db_column='birthday')
    gentoo_join_date = ListField(db_column='gentooJoin')
    gentoo_retire_date = ListField(db_column='gentooRetire')
    developer_bug = ListField(db_column='gentooDevBug')
    gpg_fingerprint = ListField(db_column='gentooGPGFingerprint')
    gpg_key = ListField(db_column='gentooGPGKey')
    latitude = IntegerField(db_column='gentooLatitude')
    longitude = IntegerField(db_column='gentooLongitude')
    location = CharField(db_column='gentooLocation')
    mentor = ListField(db_column='gentooMentor')
    im = ListField(db_column='gentooIM')
    # gentooDevGroup
    roles = CharField(db_column='gentooRoles')
    alias = ListField(db_column='gentooAlias')
    spf = ListField(db_column='gentooSPF')

    def __str__(self):
        return self.username

    def __unicode__(self):
        return self.username


# Models for OpenID data store

class OpenID_Nonce(models.Model):
    server_uri = models.URLField(max_length=2048)
    ts = models.DateTimeField()
    salt = models.CharField(max_length=40)

    class Meta:
        unique_together = ('server_uri', 'ts', 'salt')


class OpenID_Association(models.Model):
    server_uri = models.URLField(max_length=2048)
    handle = models.CharField(max_length=255)
    # TODO: BinaryField in newer versions of django
    secret = models.CharField(max_length=128)
    issued = models.DateTimeField()
    expires = models.DateTimeField()
    assoc_type = models.CharField(max_length=64)

    class Meta:
        unique_together = ('server_uri', 'handle')
