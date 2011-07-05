from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.libraries.encryption import sha1Password
from okupy.libraries.exception import OkupyException, log_extra_data
from okupy.libraries.ldap_wrappers import *
from okupy.libraries.verification import sendConfirmationEmail, checkConfirmationKey
from okupy.recover.forms import RecoverInitForm, RecoverForm
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
    try:
        if email not in user[0][1]['mail']:
            return False
    except KeyError:
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

def changeLDAPPassword(request, result, user, form):
    '''
    Update user's LDAP password
    '''
    l = ldap_admin_user_bind()
    mod_attrs = [(ldap.MOD_DELETE, 'userPassword', None)]
    mod_attrs2 = [(ldap.MOD_ADD, 'userPassword', sha1Password(form.cleaned_data['password1']))]
    try:
        l.modify_s(user[0][0], mod_attrs)
        l.modify_s(user[0][0], mod_attrs2)
    except Exception as error:
        logger.error(error, extra = log_extra_data(request))
        raise OkupyException('Could not modify LDAP data')
    l.unbind_s()
    '''
    Remove the password request entry from the RecoverPassword table
    '''
    try:
        result.delete()
    except Exception as error:
        logger.error(error, extra = log_extra_data(request))
        raise OkupyException('Could not modify DB data')

def recover_init(request):
    '''
    A form where the user fills in username and email, and gets
    a temporary URL in that email where he can update the password
    '''
    msg = ''
    form = ''
    email = ''
    if request.method == 'POST':
        form = RecoverInitForm(request.POST)
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
                username = email = None
                msg = error.value
                logger.error(msg, extra = log_extra_data(request, form))
    else:
        form = RecoverInitForm()
    return render_to_response('recover/recover.html', 
        {'msg': msg, 'form': form, 'email': email},
        context_instance = RequestContext(request))

def recover_password(request, key):
    '''
    Recover password form
    '''
    msg = ''
    form = ''
    result = ''
    if request.method == 'POST':
        form = RecoverForm(request.POST)
        if form.is_valid():
            try:
                result = checkConfirmationKey(key, RecoverPassword)
                print result
                print form.cleaned_data['password1']
                if form.cleaned_data['password1'] != form.cleaned_data['password2']:
                    raise OkupyException('Passwords don\'t match')
                user = ldap_user_search(result.user)
                print user
                changeLDAPPassword(request, result, user, form)
            except OkupyException as error:
                msg = error.value
                logger.error(msg, extra = log_extra_data(request, form))
    else:
        try:
            checkConfirmationKey(key, RecoverPassword)
            form = RecoverForm()
        except OkupyException as error:
            msg = error.value
            logger.error(msg, extra = log_extra_data(request, form))
    return render_to_response(
        'recover/password.html',
        {'msg': msg, 'form': form, 'data': result},
        context_instance = RequestContext(request))
