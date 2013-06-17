# vim:fileencoding=utf8:et:ts=4:sw=4:sts=4

from urlparse import urljoin

from django.conf import settings
from django.contrib import auth
from django.core.urlresolvers import reverse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt

import django.contrib.auth.views as auth_views

def login(request):
    return auth_views.login(request,
            template_name = 'openid/login.html')

def logout(request):
    auth.logout(request)
    return redirect('openid.index')

def index(request):
    return render(request, 'openid/index.html')

class endpoint_url:
    @classmethod
    def __str__(cls):
        return urljoin(settings.OPENID_REFERENCE_URL_PREFIX, reverse(endpoint))

def test_user(request):
    return render(request, 'openid/user.html',
            {
                'endpoint': endpoint_url
            })

@csrf_exempt
def endpoint(request):
    if request.method == 'POST':
        req = request.POST
    else:
        req = request.GET

    print req

    return render(request, 'openid/endpoint.html')
