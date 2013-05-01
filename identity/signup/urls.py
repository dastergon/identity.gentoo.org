from django.conf.urls import patterns

urlpatterns = patterns('identity.signup.views',
    (r'^$', 'signup'),
)
