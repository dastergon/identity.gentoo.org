# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.db import models
from ldapdb.models.fields import (CharField, IntegerField, ListField,
                                  FloatField, ACLField, DateField)
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
    object_classes = settings.AUTH_LDAP_USER_OBJECTCLASS
    # top
    object_class = ListField(db_column='objectClass')
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
    birthday = DateField(db_column='birthday')
    gentoo_join_date = ListField(db_column='gentooJoin')
    gentoo_retire_date = ListField(db_column='gentooRetire')
    developer_bug = ListField(db_column='gentooDevBug')
    location = CharField(db_column='gentooLocation')
    mentor = ListField(db_column='gentooMentor')
    im = ListField(db_column='gentooIM')
    gpg_fingerprint = ListField(db_column='gpgfingerprint')
    gpg_key = ListField(db_column='gpgKey')
    latitude = FloatField(db_column='lat')
    longitude = FloatField(db_column='lon')
    # gentooDevGroup
    roles = CharField(db_column='gentooRoles')
    alias = ListField(db_column='gentooAlias')
    spf = ListField(db_column='gentooSPF')
    # additional ACL fields based on gentooACL
    is_user = ACLField(db_column='gentooACL')
    is_developer = ACLField(db_column='gentooACL')
    is_foundation = ACLField(db_column='gentooACL')
    is_staff = ACLField(db_column='gentooACL')
    is_docs = ACLField(db_column='gentooACL')
    is_council = ACLField(db_column='gentooACL')
    is_trustee = ACLField(db_column='gentooACL')
    is_overlays = ACLField(db_column='gentooACL')
    is_planet = ACLField(db_column='gentooACL')
    is_wiki = ACLField(db_column='gentooACL')
    is_forums = ACLField(db_column='gentooACL')
    is_security = ACLField(db_column='gentooACL')
    is_recruiter = ACLField(db_column='gentooACL')
    is_undertaker = ACLField(db_column='gentooACL')
    is_pr = ACLField(db_column='gentooACL')
    is_infra = ACLField(db_column='gentooACL')
    is_retired = ACLField(db_column='gentooACL')

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


class OpenID_Attributes(models.Model):
    """ An attribute choice for submission to the site requesting auth.
    """

    nickname = models.NullBooleanField('Nickname', default=True)
    email = models.NullBooleanField('E-mail address', default=True)
    fullname = models.NullBooleanField('Full name', default=True)
    # XXX: OpenID allows disabling invidual components
    dob = models.NullBooleanField('Date of birth', default=True)
    gender = models.NullBooleanField('Gender', default=True)
    postcode = models.NullBooleanField('Postal code', default=True)
    country = models.NullBooleanField('Country', default=True)
    language = models.NullBooleanField('Language', default=True)
    timezone = models.NullBooleanField('Time zone', default=True)

    which_email = models.CharField(max_length=254, null=True, blank=True)
