from django.conf.urls.defaults import patterns

urlpatterns = patterns('identity.index.views',
    (r'^$', 'index'),
)
