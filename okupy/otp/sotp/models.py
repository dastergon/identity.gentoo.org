# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.db import models

from django_otp.models import Device

from django.contrib.auth.models import User

import random


class SOTPToken(models.Model):
    user = models.ForeignKey(User)
    # TODO: move to LDAPUser
    secret = models.CharField(max_length=8,
        help_text='An OTP token')

    class Meta:
        unique_together = ('user', 'secret')


class SOTPDevice(Device):
    def gen_keys(self, num=10):
        # delete old keys
        SOTPToken.objects.filter(user=self.user).delete()

        # now give the new ones
        for i in range(num):
            while True:
                k = random.randint(1E7, 1E8)
                try:
                    SOTPToken(user=self.user, secret=k).save()
                except IntegrityError:
                    pass
                else:
                    break
            yield k

    def verify_token(self, token):
        # TODO: add atomic blocking of used secrets

        try:
            token = SOTPToken.objects.get(user=self.user,
                                          secret=token)
        except SOTPToken.DoesNotExist:
            return False
        else:
            token.delete()
        return True
