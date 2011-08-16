from django.conf.urls.defaults import patterns

urlpatterns = patterns('okupy.index.views',
    (r'^$', 'index'),
)
