# vim:fileencoding=utf8:et:ts=4:sw=4:sts=4

from django.conf.urls import patterns, url

from . import views

openid_urlpatterns = patterns('',
    url(r'^login/$', views.login),
)
