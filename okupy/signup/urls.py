from django.conf.urls import patterns

urlpatterns = patterns('okupy.signup.views',
    (r'^$', 'signup'),
)
