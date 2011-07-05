from django.conf.urls.defaults import patterns
from django.views.generic.simple import redirect_to

urlpatterns = patterns('okupy.accounts.views',
    # (r'^$', redirect_to, {'url': '/account/%(username)s/'}), <--- doesn't work
    (r'^(?P<username>\w+)/$', 'account'),
    (r'^(?P<username>\w+)/edit/$', 'account_edit'),
    (r'^(?P<username>\w+)/edit/password/$', 'account_edit_password'),
    (r'^(?P<username>\w+)/edit/email/$', 'account_edit_email'),
)
