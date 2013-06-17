from django.conf.urls import patterns, include, url
from okupy.accounts.views import login, index, signup, activate

from .openid.urls import openid_urlpatterns

urlpatterns = patterns('',
    (r'^$', index),
    (r'^login/$', login),
    (r'^signup/$', signup),
    (r'^activate/(?P<token>[a-zA-Z0-9]+)/$', activate),

    (r'^openid/', include(openid_urlpatterns))
)
