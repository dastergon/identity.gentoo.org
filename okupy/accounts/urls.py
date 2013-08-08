# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python
from django.conf.urls import patterns, url

from . import views as v

accounts_urlpatterns = patterns('',
    url(r'^$', v.index),
    url(r'^login/$', v.login),
    url(r'^ssl-auth/$', v.ssl_auth),
    url(r'^logout/$', v.logout),
    url(r'^devlist/$', v.DevListsView.as_view(template_name='devlist.html')),
    url(r'^former-devlist/$', v.DevListsView.as_view(template_name='former-devlist.html')),
    url(r'^foundation-members/$', v.DevListsView.as_view(template_name='foundation-members.html')),
    url(r'^signup/$', v.signup),
    url(r'^activate/(?P<token>[a-zA-Z0-9]+)/$', v.activate),
    url(r'^otp-setup/$', v.otp_setup),
    url(r'^endpoint/$', v.openid_endpoint),
    url(r'^id/(.*)/$', v.user_page),
    url(r'^auth-site/$', v.openid_auth_site),
)
