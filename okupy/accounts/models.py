# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python
from django.db import models

class Queue(models.Model):
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=30)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=254, unique=True)
    token = models.CharField(max_length=40)
