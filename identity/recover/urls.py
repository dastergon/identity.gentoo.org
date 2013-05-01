from django.conf.urls.defaults import patterns

urlpatterns = patterns('identity.recover.views',
    (r'^$', 'recover_init'),
    (r'^(?P<key>[a-zA-Z0-9]+)/$', 'recover_password', {}, 'recover_password'),
)
