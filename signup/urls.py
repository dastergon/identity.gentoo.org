from django.conf.urls.defaults import patterns

urlpatterns = patterns('okupy.signup.views',
    (r'^$', 'signup'),
)
