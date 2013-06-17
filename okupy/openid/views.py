# vim:fileencoding=utf8:et:ts=4:sw=4:sts=4

import django.contrib.auth.views as auth_views

def login(request):
    return auth_views.login(request,
            template_name = 'openid/login.html')
