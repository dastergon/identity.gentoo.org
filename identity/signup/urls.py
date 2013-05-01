from django.conf.urls.defaults import patterns

urlpatterns = patterns('identity.signup.views',
    (r'^$', 'signup'),
)
