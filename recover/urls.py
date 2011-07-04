from django.conf.urls.defaults import patterns

urlpatterns = patterns('okupy.recover.views',
    (r'^$', 'recover'),
)
