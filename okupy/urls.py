from django.conf.urls import patterns, include, url
from okupy.accounts.views import login, index, signup, activate

urlpatterns = patterns('',
    (r'^$', index),
    (r'^login/$', login),
    (r'^signup/$', signup),
    (r'^activate/(?P<token>[a-zA-Z0-9]+)/$', activate),
)
