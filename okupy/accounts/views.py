# -*- coding: utf-8 -*-

from django.contrib.auth import login, authenticate
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.accounts.forms import LoginForm
from okupy.common.exceptions import OkupyError, LoginError

def index(request):
   return render_to_response('index.html', {}, context_instance = RequestContext(request))

def accounts_login(request):
    '''
    The login page
    '''
    notification = {}
    login_form = None
    user = None
    if request.method == "POST":
        login_form = LoginForm(request.POST)
        try:
            if login_form.is_valid():
                username = login_form.cleaned_data['username']
                password = login_form.cleaned_data['password']
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
                if not login_form.cleaned_data['remember']:
                    request.session.set_expiry(0)
                return HttpResponseRedirect('/')
        except LoginError as error:
            notification['error'] = error.value
    else:
        if request.user.is_authenticated():
            return HttpResponseRedirect('/')
        else:
            login_form = LoginForm()
    return render_to_response('login.html', {
        'notification': notification,
        'login_form': login_form,
    }, context_instance = RequestContext(request))
