from django.conf.urls.defaults import patterns, include, url
from django.views.generic.simple import redirect_to

urlpatterns = patterns('okupy.accounts.views',
    url(r'^$', redirect_to, {'url': '^(?P<username>\w+)/$', 'permanent': True}),
    url(r'^(?P<username>\w+)/$', 'account'),
    url(r'^edit(?P<username>\d+)/$', 'account_edit'),
)
