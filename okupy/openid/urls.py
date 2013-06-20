# vim:fileencoding=utf8:et:ts=4:sw=4:sts=4

from django.conf.urls import patterns, url

from . import views

openid_urlpatterns = patterns('',
    url(r'^$', views.index, name='openid.index'),
    url(r'^login/$', views.login, name='openid.login'),
    url(r'^logout/$', views.logout, name='openid.logout'),
    url(r'^endpoint/$', views.endpoint, name='openid.endpoint'),
    url(r'^auth-site/$', views.auth_site, name='openid.auth_site'),
    url(r'^id/(\w+)/$', views.user_page, name='openid.user_page'),
)
