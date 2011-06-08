from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from okupy.login.views import *
from okupy.user.views import *

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^login/$', mylogin),
    url(r'^$', user),
    url(r'^admin/', include(admin.site.urls)),
)
