from django.conf.urls.defaults import patterns

urlpatterns = patterns('okupy.login.views',
    (r'^login/', 'mylogin'),
    (r'^logout/', 'mylogout'),
)
