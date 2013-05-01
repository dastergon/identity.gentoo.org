from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from identity.login.views import mylogin, mylogout

admin.autodiscover()

urlpatterns = patterns('',
    #(r'^$', include('login.urls')), <-- doesn't work
    (r'^$', include('identity.index.urls')),
    (r'^account/', include('identity.accounts.urls')),
    (r'^login/$', mylogin),
    (r'^logout/$', mylogout),
    (r'^recover/', include('identity.recover.urls')),
    (r'^signup/', include('identity.signup.urls')),
    (r'^verification/', include('identity.verification.urls')),
)
