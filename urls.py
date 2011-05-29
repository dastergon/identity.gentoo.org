from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from okupy.login.views import *

admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'okupy.views.home', name='home'),
    # url(r'^okupy/', include('okupy.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),

	url(r'^$', mylogin)
)
