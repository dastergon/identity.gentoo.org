# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python
from django.conf.urls import patterns, url
from .views import (DevListsView, ssl_auth, login, logout, index, signup,
        activate, openid_endpoint, user_page, openid_auth_site)

accounts_urlpatterns = patterns('',
    url(r'^$', index),
    url(r'^login/$', login),
    url(r'^ssl-auth/$', ssl_auth),
    url(r'^logout/$', logout),
    url(r'^devlist/$', DevListsView.as_view(template_name='devlist.html')),
    url(r'^former-devlist/$', DevListsView.as_view(template_name='former-devlist.html')),
    url(r'^foundation-members/$', DevListsView.as_view(template_name='foundation-members.html')),
    url(r'^signup/$', signup),
    url(r'^activate/(?P<token>[a-zA-Z0-9]+)/$', activate),
    url(r'^endpoint/$', openid_endpoint),
    url(r'^id/(.*)/$', user_page),
    url(r'^auth-site/$', openid_auth_site),
)
