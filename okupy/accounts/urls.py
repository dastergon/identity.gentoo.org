# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python
from django.conf.urls import patterns, url

from . import views as v

accounts_urlpatterns = patterns('',
    url(r'^$', v.index, name="index"),
    url(r'^login/$', v.login),
    url(r'^ssl-auth/$', v.ssl_auth),
    url(r'^logout/$', v.logout, name="logout"),
    url(r'^devlist/$', v.lists, {'acc_list': 'devlist'}, name="active_developers"),
    url(r'^former-devlist/$', v.lists, {'acc_list': 'former-devlist'}, name="former_developers"),
    url(r'^foundation-members/$', v.lists, {'acc_list': 'foundation-members'}, name="foundation_members"),
    url(r'^signup/$', v.signup),
    url(r'^activate/(?P<token>[a-zA-Z0-9-_]+)/$', v.activate),
    url(r'^otp-setup/$', v.otp_setup),
    url(r'^otp-qrcode.png$', v.otp_qrcode),
    url(r'^endpoint/$', v.openid_endpoint),
    url(r'^id/(.*)/$', v.user_page),
    url(r'^auth-site/$', v.openid_auth_site),
)
