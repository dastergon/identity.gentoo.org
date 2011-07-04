from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from okupy.login.views import mylogin, mylogout

admin.autodiscover()

urlpatterns = patterns('',
    #(r'^$', include('login.urls')), <-- doesn't work
    (r'^$', include('index.urls')),
    (r'^account/', include('accounts.urls')),
    (r'^admin/', include(admin.site.urls)),
    (r'^login/$', mylogin),
    (r'^logout/$', mylogout),
    (r'^recover/$', include('recover.urls')),
    (r'^signup/', include('signup.urls')),
    (r'^verification/', include('verification.urls')),
)
