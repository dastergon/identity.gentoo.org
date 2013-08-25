# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

import base64
import calendar
import datetime
import time

from django.db import IntegrityError
from django.utils import timezone

from openid.store.interface import OpenIDStore
from openid.association import Association
from openid.store import nonce

from okupy.accounts import models as db_models


class DjangoDBOpenIDStore(OpenIDStore):

    def storeAssociation(self, server_uri, assoc):
        issued_dt = datetime.datetime.utcfromtimestamp(assoc.issued)
        issued_dt = timezone.make_aware(issued_dt, timezone.utc)
        expire_delta = datetime.timedelta(seconds=assoc.lifetime)

        a = db_models.OpenID_Association(
            server_uri=server_uri,
            handle=assoc.handle,
            secret=base64.b64encode(assoc.secret),
            issued=issued_dt,
            expires=issued_dt + expire_delta,
            assoc_type=assoc.assoc_type)
        a.save()

    def _db_getAssocs(self, server_uri, handle=None):
        objs = db_models.OpenID_Association.objects
        objs = objs.filter(server_uri=server_uri)
        if handle is not None:
            objs = objs.filter(handle=handle)

        return objs

    def getAssociation(self, server_uri, handle=None):
        assert(server_uri is not None)

        objs = self._db_getAssocs(server_uri, handle)
        try:
            a = objs.latest('issued')
        except db_models.OpenID_Association.DoesNotExist:
            return None

        # expired?
        if timezone.now() >= a.expires:
            # if latest is expired, all older are expired as well
            # so clean them all up
            objs.delete()
            return None

        return Association(
            a.handle,
            base64.b64decode(a.secret),
            calendar.timegm(a.issued.utctimetuple()),
            int((a.expires - a.issued).total_seconds()),
            a.assoc_type)

    def removeAssociation(self, server_uri, handle):
        assert(server_uri is not None)
        assert(handle is not None)

        objs = self._db_getAssocs(server_uri, handle)

        # determining whether something was deleted is a waste of time
        # and django doesn't give us explicit 'affected rows'
        return True

    def useNonce(self, server_uri, ts, salt):
        nonce_dt = datetime.datetime.utcfromtimestamp(ts)
        nonce_dt = timezone.make_aware(nonce_dt, timezone.utc)
        # copy-paste from python-openid's sqlstore
        if abs((nonce_dt - timezone.now()).total_seconds()) > nonce.SKEW:
            return False

        n = db_models.OpenID_Nonce(
            server_uri=server_uri,
            ts=nonce_dt,
            salt=salt)
        try:
            n.save()
        except IntegrityError:
            # non-unique
            return False
        return True

    def cleanupNonces(self):
        skew_td = datetime.timedelta(seconds=nonce.SKEW)
        expire_dt = timezone.now() - skew_td

        db_models.OpenID_Nonce.objects.filter(ts__lt=expire_dt).delete()
        return 0

    def cleanupAssociations(self):
        db_models.OpenID_Association.objects.filter(
            expires__lt=timezone.now()).delete()
        return 0
