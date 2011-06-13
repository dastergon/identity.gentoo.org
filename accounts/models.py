from django.conf import settings
from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    '''
    Creates 1-to-1 relationship with Django User model
    for adding custom fields
    '''
    user = models.ForeignKey(User, unique = True)
    cn = models.CharField(max_length = 15, blank = True, null = True)
    all_mails = models.TextField(blank = True, null = True)
    gecos = models.CharField(max_length = 50)
    ssh_public_key = models.TextField(blank = True, null = True)
    gpg_key = models.TextField(blank = True, null = True)
    gpg_fingerprint = models.TextField(blank = True, null = True)
    lat = models.CharField(max_length = 15, blank = True, null = True)
    lon = models.CharField(max_length = 15, blank = True, null = True)

class GentooDevProfile(UserProfile):
    gentoo_status = models.CharField(max_length = 15)
    gentoo_access = models.TextField()
    gentoo_location = models.CharField(max_length = 50)
    gentoo_roles = models.CharField(max_length = 50)
    is_infra = models.BooleanField(default = False)
    is_devrel = models.BooleanField(default = False)
    is_recruiter = models.BooleanField(default = False)
    is_trustee = models.BooleanField(default = False)
    is_docs = models.BooleanField(default = False)
    is_security = models.BooleanField(default = False)