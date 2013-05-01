from django.conf.urls.defaults import patterns

urlpatterns = patterns('identity.login.views',
    (r'^login/', 'mylogin'),
    (r'^logout/', 'mylogout'),
)
