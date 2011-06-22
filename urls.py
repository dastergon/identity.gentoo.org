from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from okupy.login.views import *
from okupy.signup.views import *

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^login/$', mylogin),
    url(r'^$', include('index.urls')),
    url(r'^signup/', signup),
    url(r'^account/', include('accounts.urls')),
    url(r'^admin/', include(admin.site.urls)),
)
