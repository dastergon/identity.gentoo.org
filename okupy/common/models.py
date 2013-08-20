# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models, IntegrityError

from .crypto import idcipher

from datetime import datetime, timedelta


# based on https://gist.github.com/treyhunner/735861

class EncryptedPKModelManager(models.Manager):
    def get(self, *args, **kwargs):
        eid = kwargs.pop('encrypted_id', None)
        if eid is not None:
            kwargs['id'] = idcipher.decrypt(eid)
        return super(EncryptedPKModelManager, self).get(*args, **kwargs)


class EncryptedPKModel(models.Model):
    """
    A model with built-in identifier encryption (for secure tokens).
    """

    objects = EncryptedPKModelManager()

    @property
    def encrypted_id(self):
        """
        The object identifier encrypted using IDCipher, as a hex-string.
        """
        if self.id is None:
            return None
        return idcipher.encrypt(self.id)

    class Meta:
        abstract = True


class RevokedToken(models.Model):
    """
    A model that guarantees atomic token revocation.

    We can use a single table for various kinds of tokens as long
    as they don't interfere (e.g. are of different length).
    """

    user = models.ForeignKey(User, db_index=False, null=True)
    token = models.CharField(max_length=64)
    ts = models.DateTimeField(auto_now_add=True)

    @classmethod
    def cleanup(cls):
        """
        Remove tokens old enough to be no longer valid.
        """

        # we use this just to enforce atomicity and prevent replay
        # for SOTP, we can clean up old tokens quite fast
        # (as soon as .delete() is effective)
        # for TOTP, we should wait till the token drifts away
        old = datetime.now() - timedelta(minutes=3)
        cls.objects.filter(ts__lt=old).delete()

    @classmethod
    def add(cls, token, user=None):
        """
        Use and revoke the given token, for the given user. User
        can be None if irrelevant.

        Returns True if the token is fine, False if it was used
        already.
        """
        cls.cleanup()

        t = cls(user=user, token=token)
        try:
            t.save()
        except IntegrityError:
            return False
        return True

    class Meta:
        unique_together = ('user', 'token')
