# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.db import models

from .crypto import idcipher


# based on https://gist.github.com/treyhunner/735861

class EncryptedPKModelManager(models.Manager):
    def get(self, *args, **kwargs):
        eid = kwargs.pop('encrypted_id', None)
        if eid is not None:
            kwargs['id'] = idcipher.decrypt(eid)
        return super(EncryptedPKModelManager, self).get(*args, **kwargs)


class EncryptedPKModel(models.Model):
    objects = EncryptedPKModelManager()

    @property
    def encrypted_id(self):
        if self.id is None:
            return None
        return idcipher.encrypt(self.id)

    class Meta:
        abstract = True
