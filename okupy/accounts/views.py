# -*- coding: utf-8 -*-

from django.contrib.auth import login, authenticate
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.accounts.forms import LoginForm
from okupy.common.exceptions import OkupyError, LoginError

def accounts_login(request):
    '''
    The login page
    '''
    notification = {}
    form = None
    user = None
    if request.method == "POST":
        form = LoginForm(request.POST)
        try:
            if form.is_valid():
                username = form.cleaned_data['username']
                password = form.cleaned_data['password']
            else:
                raise LoginError
            '''
            Perform authentication, if it retrieves a user object then
            it was successful. If it retrieves None then it failed to login
            '''
            user = authenticate(username = username, password = password)
            if not user:
                raise LoginError
            if user.is_active:
                login(request, user)
                if not form.cleaned_data['remember']:
                    request.session.set_expiry(0)
                return HttpResponseRedirect('/')
        except LoginError as error:
            notification['error'] = error.value
    else:
        if request.user.is_authenticated():
            return HttpResponseRedirect('/')
        else:
            form = LoginForm()
    return render_to_response('login.html', {
        'notification': notification,
        'form': form,
    }, context_instance = RequestContext(request))
