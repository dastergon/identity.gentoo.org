# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class ExternalBackend(ModelBackend):
    """ Authentication backend that relies on an external,
    non-password authentication. """

    def authenticate(self, username=None, ext_authed=False):
        if not ext_authed:
            return None

        UserModel = get_user_model()

        user, created = UserModel.objects.get_or_create(**{
            UserModel.USERNAME_FIELD: username
        })
        return user
