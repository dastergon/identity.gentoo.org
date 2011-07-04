from okupy.accounts.models import *
from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.libraries.encryption import random_string
from okupy.libraries.exception import OkupyException, log_extra_data
from okupy.libraries.ldap_wrappers import *
from okupy.verification.models import InactiveEmail
import logging

logger = logging.getLogger('okupy')

def sendConfirmationEmail(request, credentials, form):
    '''
    Create a random URL and send an email to the user to confirm his email address
    '''
    random_url = random_string(30)
    inactive_email = InactiveEmail(email = credentials['email'],
                                    user = credentials['username'],
                                    url = random_url)
    try:
        inactive_email.save()
    except Exception as error:
        logger.error(error, extra = log_extra_data(request, form))
        raise OkupyException('Could not save to DB')
    send_mail('[Okupy]: Please confirm your email address',
        'To confirm your email address, please click <a href="/%s">here</a>' % random_url,
        'admin@tampakrap.gr',
        [credentials['email']])

def checkConfirmationKey(key):
    '''
    Check if the URL matches any of the confirmation keys in the database
    '''
    try:
        result = InactiveEmail.objects.get(url = key)
    except InactiveEmail.DoesNotExist as error:
        raise OkupyException('URL not found')
    return result

def addEmailToLDAP(request, result, user):
    '''
    Update user's mail list in LDAP
    '''
    l = ldap_admin_user_bind()
    mod_attrs = [(ldap.MOD_ADD, 'mail', str(result.email))]
    try:
        l.modify_s(user[0][0], mod_attrs)
    except Exception as error:
        logger.error(error, extra = log_extra_data(request))
        raise OkupyException('Could not modify LDAP data')
    l.unbind_s()
    '''
    Check if the user is also in the DB, and update the mail list there
    as well
    '''
    try:
        db_user = User.objects.get(username = user[0][1]['uid'][0])
    except User.DoesNotExist:
        pass
    else:
        db_user_profile = db_user.get_profile()
        if not db_user.get_profile().all_mails:
            db_user_profile.all_mails = result.email
        else:
            db_user_profile.all_mails += '::%s' % result.email
        try:
            db_user_profile.save()
        except Exception as error:
            logger.error(error, extra = log_extra_data(request))
            raise OkupyException('Could not save to DB')
    '''
    Remove the email from the table with the Inactive ones
    '''
    try:
        result.delete()
    except Exception as error:
        logger.error(error, extra = log_extra_data(request))
        raise OkupyException('Could not modify DB data')

def verification(request, key):
    '''
    Verify email account
    '''
    msg = ''
    result = ''
    try:
        '''
        Check if the given URL exists in the database, and if the user exists
        in the LDAP server, and afterwards try to update the user's email
        list in LDAP
        '''
        result = checkConfirmationKey(key)
        user = ldap_user_search(result.user)
        if user:
            addEmailToLDAP(request, result, user)
    except OkupyException as error:
        msg = error.value
        logger.error(msg, extra = log_extra_data(request))
    return render_to_response(
        'verification.html',
        {'msg': msg, 'data': result},
        context_instance = RequestContext(request))
