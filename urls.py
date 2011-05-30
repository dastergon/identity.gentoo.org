from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from okupy.login.views import *

admin.autodiscover()

urlpatterns = patterns('',
	url(r'^$', mylogin),
    url(r'^admin/', include(admin.site.urls)),
)
