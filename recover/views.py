from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.libraries.exception import OkupyException, log_extra_data
from okupy.libraries.ldap_wrappers import ldap_user_search
from okupy.libraries.verification import sendConfirmationEmail
from okupy.recover.forms import RecoverForm
from okupy.recover.models import RecoverPassword
import logging

logger = logging.getLogger('okupy')

def checkUserEmail(username, email):
    '''
    Check if the username exists
    '''
    user = ldap_user_search(username)
    if not user:
        return False
    '''
    Check if the email belongs to the above username
    '''
    if email not in user[0][1]['mail']:
        return False
    '''
    Check if the user has already requested for a
    password reset
    '''
    # TODO
    # What to do here? Options:
    # 1) Remove previous entry from the DB
    # 2) Print error
    return user

def recover(request):
    '''
    Recover password. User fills in username and email in a simple form,
    and he gets a temporary URL where he can update the password
    '''
    msg = ''
    form = ''
    email = ''
    if request.method == 'POST':
        form = RecoverForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            try:
                user = checkUserEmail(username, email)
                if not user:
                    raise OkupyException('User not found')
                else:
                    user = user[0][1]
                sendConfirmationEmail(request, form, RecoverPassword)
            except OkupyException as error:
                msg = error.value
                logger.error(msg, extra = log_extra_data(request, form))
    else:
        form = RecoverForm()
    return render_to_response('recover/recover.html', 
        {'msg': msg, 'form': form, 'email': email},
        context_instance = RequestContext(request))
