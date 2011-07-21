from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from okupy.accounts.fields import OkupyMultiField

class OkupyMultiModelField(models.Field):
    def formfield(self, **kwargs):
        defaults = {'form_class': OkupyMultiField}
        defaults.update(kwargs)
        return super(OkupyMultiModelField, self).formfield(**defaults)

    def get_internal_type(self):
        return 'TextField'

class UserProfile(models.Model):
    '''
    Creates 1-to-1 relationship with Django User model
    for adding custom fields
    '''
    user = models.ForeignKey(User, unique = True)
    cn = models.CharField(max_length = 15, blank = True, null = True)
    mail = OkupyMultiModelField()
    secondary_password = models.CharField(max_length = 50, blank = True, null = True)
    base_dn = models.CharField(max_length = 50)
    objectClass = OkupyMultiModelField()

    class Meta:
        abstract = True

class GentooProfile(UserProfile):
    '''
    Extends the above UserProfile class with Gentoo-specific DB fields
    '''
    birthday = models.CharField(max_length = 10)
    gentooAccess = OkupyMultiModelField()
    gentooIm = OkupyMultiModelField()
    gentooJoin = models.CharField(max_length = 10)
    gentooLocation = models.CharField(max_length = 50)
    gentooRoles = models.CharField(max_length = 100)
    gentooSPF = models.CharField(max_length = 50)
    gentooStatus = models.CharField(max_length = 15)
    gpgkey = OkupyMultiModelField()
    gpgfingerprint = OkupyMultiModelField()
    lat = models.CharField(max_length = 15, blank = True, null = True)
    lon = models.CharField(max_length = 15, blank = True, null = True)
    sshPublicKey = OkupyMultiModelField()
    gecos = models.CharField(max_length = 50)
    is_infra = models.BooleanField(default = False)
    is_devrel = models.BooleanField(default = False)
    is_recruiter = models.BooleanField(default = False)
    is_trustee = models.BooleanField(default = False)
    is_docs = models.BooleanField(default = False)
    is_security = models.BooleanField(default = False)
    is_pr = models.BooleanField(default = False)
