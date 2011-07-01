from django.conf import settings
from django.contrib.auth.decorators import login_required
#from django.forms.models import modelformset_factory
from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.accounts.backends import LDAPBackend
from okupy.accounts.models import *
from okupy.libraries.exception import OkupyException, log_extra_data
from okupy.libraries.ldap_wrappers import ldap_user_search
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

@login_required
def account(request, username):
    msg = ''
    user = ''
    try:
        if not checkUsername(request, username):
            raise OkupyException('Invalid URL')
        user = LDAPBackend()
        user = user.get_or_create_user(username = username, other = True)
    except OkupyException as error:
        msg = error.value
        logger.error(msg, extra = log_extra_data(request))
    return render_to_response(
        'account/account.html',
        {'current_user': user, 'msg': msg},
        context_instance = RequestContext(request))

@login_required
def account_edit(request, username):
    msg = ''
    form = ''
    try:
        '''
        Check if the user is a member of the privileged
        groups that has permissions to edit other users' data
        '''
        for key in settings.LDAP_ACL_GROUPS_EDIT:
            if getattr(request.user.get_profile(), key):
                priv = True
                break
            else:
                priv = False
        if not request.user.username == username and not priv:
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
        user_profile_priv_form = eval(settings.AUTH_PROFILE_MODULE.split('accounts.')[1] + 'PrivForm')
        instance = user_profile.objects.get(user__username = username)
        if request.method == 'POST':
            if priv:
                form = user_profile_priv_form(request.POST, instance = instance)
            else:
                form = user_profile_form(request.POST, instance = instance)
            if form.is_valid():
                # TODO
                # Bind as the current user, and update the fields both in LDAP and DB
                print 'todo'
        else:
            if priv:
                form = user_profile_priv_form(instance = instance)
            else:
                form = user_profile_form(instance = instance)
    except OkupyException as error:
        msg = error.value
        logger.error(msg, extra = log_extra_data(request))
    return render_to_response(
        'account/edit.html',
        {'form': form, 'msg': msg},
        context_instance = RequestContext(request))
