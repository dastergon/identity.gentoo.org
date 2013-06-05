from django.conf.urls import patterns, include, url
from okupy.accounts.views import login, index

urlpatterns = patterns('',
    (r'^$', index),
    (r'^login/$', login),
)
