from django.conf.urls import patterns, include, url
from okupy.accounts.views import accounts_login, index

urlpatterns = patterns('',
    (r'^$', index),
    (r'^login/$', accounts_login),
)
