from django.conf.urls.defaults import patterns, include, url

urlpatterns = patterns('okupy.index.views',
    url(r'^$', 'index'),
)