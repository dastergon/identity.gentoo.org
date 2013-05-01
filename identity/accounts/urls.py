from django.conf.urls.defaults import patterns

urlpatterns = patterns('identity.accounts.views',
    (r'^(?P<username>\w+)/$', 'account'),
	(r'^all/$', 'account_all'),
    (r'^(?P<username>\w+)/edit/$', 'account_edit'),
    (r'^(?P<username>\w+)/edit/password/$', 'account_edit_password'),
    (r'^(?P<username>\w+)/edit/email/$', 'account_edit_email'),
)
