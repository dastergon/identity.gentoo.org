from django.conf.urls import patterns, include, url
from okupy.accounts.views import accounts_login

urlpatterns = patterns('',
    (r'^login/$', accounts_login),
)
