from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.accounts.backends import LDAPBackend
from okupy.accounts.models import *
from okupy.libraries.exception import OkupyException, log_extra_data
import logging

logger = logging.getLogger('okupy')

def checkUsername(request, username):
    '''
    Check if the username given in the URL is correct
    '''
    if username == request.user.username or ldap_user_search(username):
        return True
    else:
        return False

def checkPrivilegedUser(request, username):
    '''
    Check if the user is a member of the privileged
    groups that has permissions to edit other users' data
    '''
    for item in settings.LDAP_ACL_GROUPS_EDIT:
        if getattr(request.user.get_profile(), item):
            return True
    return False

@login_required
def account(request, username):
    msg = ''
    user = ''
    try:
        if not checkUsername(request, username):
            raise OkupyException('Invalid URL')
        '''
        If the user is not in the DB already, he should be transfered from
        the LDAP
        '''
        current_user = LDAPBackend()
        current_user = current_user.get_or_create_user(username = username, other = True)
        '''
        Create a dictionary with all the user's data, and keep only the ones that
        should be public
        '''
        current_user_profile = eval(settings.AUTH_PROFILE_MODULE.split('accounts.')[1]).objects.get(user__username = username)
        current_user_full = dict(current_user.__dict__.items() + current_user_profile.__dict__.items())
        privil = checkPrivilegedUser(request, username)
        if not request.user.username == username not privil:
            for key in current_user_full.keys():
                if key not in settings.LDAP_PROFILE_PUBLIC_ATTRIBUTES:
                    del current_user_full[key]
    except OkupyException as error:
        msg = error.value
        logger.error(msg, extra = log_extra_data(request))
    return render_to_response(
        'account/account.html',
        {'current_user': current_user_full, 'msg': msg},
        context_instance = RequestContext(request))

@login_required
def account_edit(request, username):
    msg = ''
    form = ''
    try:
        privil = checkPrivilegedUser(request, username)
        if not request.user.username == username and not privil:
            raise OkupyException('Invalid URL')
        if not checkUsername(request, username):
            raise OkupyException('Invalid URL')
        '''
        If the user is not in the DB already, he should be transfered from
        the LDAP
        '''
        user = LDAPBackend()
        user = user.get_or_create_user(username = username, other = True)

        user_profile = eval(settings.AUTH_PROFILE_MODULE.split('accounts.')[1])
        user_profile_form = eval(settings.AUTH_PROFILE_MODULE.split('accounts.')[1] + 'Form')
        user_profile_privil_form = eval(settings.AUTH_PROFILE_MODULE.split('accounts.')[1] + 'PrivForm')
        instance = user_profile.objects.get(user__username = username)
        if request.method == 'POST':
            if priv:
                form = user_profile_privil_form(request.POST, instance = instance)
            else:
                form = user_profile_form(request.POST, instance = instance)
            if form.is_valid():
                # TODO
                # Bind as the current user, and update the fields both in LDAP and DB
                print 'todo'
        else:
            if priv:
                form = user_profile_privil_form(instance = instance)
            else:
                form = user_profile_form(instance = instance)
    except OkupyException as error:
        msg = error.value
        logger.error(msg, extra = log_extra_data(request))
    return render_to_response(
        'account/edit.html',
        {'form': form, 'msg': msg},
        context_instance = RequestContext(request))
