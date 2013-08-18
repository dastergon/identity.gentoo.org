# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django_otp.models import Device

from ...accounts.models import LDAPUser
from ..models import RevokedToken

import random


class SOTPDevice(Device):
    def gen_keys(self, user, num=10):
        new_keys = set()

        # generate the new keys the fun way
        # we're using a set to filter out duplicates
        # so we can just add to it till we have enough unique keys
        while len(new_keys) < num:
            new_keys.add(str(random.randint(1E7, 1E8)))

        user.otp_recovery_keys = new_keys
        user.save()
        return new_keys

    def verify_token(self, token):
        # ensure atomic revocation
        if not RevokedToken.add(self.user, token):
            return False

        u = LDAPUser.objects.get(username = self.user.username)
        if token in u.otp_recovery_keys:
            u.otp_recovery_keys.remove(token)
            u.save()
            return True
        return False
