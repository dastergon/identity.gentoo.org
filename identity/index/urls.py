from django.conf.urls import patterns

urlpatterns = patterns('identity.index.views',
    (r'^$', 'index'),
)
