# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.contrib.auth.models import User
from django.db import models, IntegrityError

from datetime import datetime, timedelta


class RevokedToken(models.Model):
    """ A model that guarantees atomic token revocation. """

    user = models.ForeignKey(User)
    token = models.CharField(max_length=10)
    ts = models.DateTimeField(auto_now_add=True)

    @classmethod
    def cleanup(cls):
        # we use this just to enforce atomicity and prevent replay
        # for SOTP, we can clean up old tokens quite fast
        # (as soon as .delete() is effective)
        # for TOTP, we should wait till the token drifts away
        old = datetime.now() - timedelta(minutes=3)
        cls.objects.filter(ts__lt=old).delete()

    @classmethod
    def add(cls, user, token):
        cls.cleanup()

        t = cls(user=user, token=token)
        try:
            t.save()
        except IntegrityError:
            return False
        return True

    class Meta:
        unique_together = ('user', 'token')
