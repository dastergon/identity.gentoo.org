# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.db import models

class Queue(models.Model):
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=30)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=254, unique=True)
    token = models.CharField(max_length=40)

# Models for OpenID data store

class OpenID_Nonce(models.Model):
    class Meta:
        unique_together = ('server_uri', 'ts', 'salt')

    server_uri = models.URLField(max_length = 2048)
    ts = models.DateTimeField()
    salt = models.CharField(max_length = 40)

class OpenID_Association(models.Model):
    class Meta:
        unique_together = ('server_uri', 'handle')

    server_uri = models.URLField(max_length = 2048)
    handle = models.CharField(max_length = 255)
    # XXX: BinaryField in newer versions of django
    secret = models.CharField(max_length = 128)
    issued = models.DateTimeField()
    expires = models.DateTimeField()
    assoc_type = models.CharField(max_length = 64)

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
