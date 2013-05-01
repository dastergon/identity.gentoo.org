from django.conf.urls import patterns

urlpatterns = patterns('identity.login.views',
    (r'^login/', 'mylogin'),
    (r'^logout/', 'mylogout'),
)
