from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from okupy.login.views import *
from okupy.signup.views import *

admin.autodiscover()

urlpatterns = patterns('',
    (r'^$', include('index.urls')),
    (r'^account/', include('accounts.urls')),
    (r'^admin/', include(admin.site.urls)),
    (r'^login/$', mylogin),
    (r'^logout/$', mylogout),
    (r'^signup/', include('signup.urls')),
    
)
