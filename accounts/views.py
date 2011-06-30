from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.accounts.backends import LDAPBackend
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
        raise OkupyException('Invalid URL')

@login_required
def account(request, username):
    msg = ''
    user = ''
    try:
        checkUsername(request, username)
        user = LDAPBackend()
        user = user.get_or_create_user(username = username, other = True)
    except OkupyException as error:
        msg = error.value
        logger.error(msg, extra = log_extra_data(request))
    return render_to_response('account/account.html', {'current_user': user, 'msg': msg}, context_instance = RequestContext(request))

@login_required
def account_edit(request, username):
    return render_to_response('account/edit.html', {}, context_instance = RequestContext(request))
