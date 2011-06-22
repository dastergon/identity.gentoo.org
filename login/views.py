from django import http
from django.contrib.auth import login, authenticate, logout
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext, loader
from okupy.login.forms import *
from okupy.libraries.exception import OkupyException, log_extra_data
import logging

logger = logging.getLogger('okupy')

def mylogin(request):
    msg = ''
    form = ''
    if request.method == 'POST':
        if request.POST.get('signup'):
            return HttpResponseRedirect('/signup')
        form = LoginForm(request.POST)
        username = request.POST.get('username')
        password = request.POST.get('password')
        try:
            user = authenticate(username = username, password = password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    if not request.POST.get('remember'):
                        request.session.set_expiry(0)
                    return HttpResponseRedirect('/user')
            else:
                msg = 'Wrong Credentials'
        except OkupyException as error:
            msg = error.value
            logger.error(msg, extra = log_extra_data(request, form))
    else:
        if request.user.is_authenticated():
            return HttpResponseRedirect('/')
        else:
            form = LoginForm()
    return render_to_response('login.html', {
            'msg': msg,
            'form': form,
        }, context_instance = RequestContext(request))

def mylogout(request):
    logout(request)
    return HttpResponseRedirect('/')

def server_error(request, template_name='500.html'):
    """
    override 500 error page, in order to pass MEDIA_URL to Context
    """
    t = loader.get_template(template_name) # You need to create a 500.html template.
    return http.HttpResponseServerError(t.render(RequestContext(request, {'request_path': request.path})))
