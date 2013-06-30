# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python
from django.conf.urls import patterns, include

from .accounts.urls import accounts_urlpatterns

urlpatterns = patterns('',
    (r'^', include(accounts_urlpatterns)),
)
