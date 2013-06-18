# vim:fileencoding=utf8:et:ts=4:sw=4:sts=4

from django.db import models

class Nonce(models.Model):
    class Meta:
        unique_together = ('server_uri', 'ts', 'salt')

    server_uri = models.URLField(max_length = 2048)
    ts = models.DateTimeField()
    salt = models.CharField(max_length = 40)

class Association(models.Model):
    class Meta:
        unique_together = ('server_uri', 'handle')

    server_uri = models.URLField(max_length = 2048)
    handle = models.CharField(max_length = 255)
    # XXX: BinaryField in newer versions of django
    secret = models.CharField(max_length = 128)
    issued = models.DateTimeField()
    expires = models.DateTimeField()
    assoc_type = models.CharField(max_length = 64)
