from django.conf import settings
from django.core.mail import send_mail
from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.libraries.encryption import random_string
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
    ldap_admin_user_username = settings.LDAP_ADMIN_USER_DN.split('=')[1].split(',')[0]
    ldap_admin_user_attr = settings.LDAP_ADMIN_USER_DN.split('=')[0]
    ldap_admin_user_base_dn = ','.join(settings.LDAP_ADMIN_USER_DN.split(',')[1:])
    l = ldap_bind(ldap_admin_user_username,
                    settings.LDAP_ADMIN_USER_PW,
                    ldap_admin_user_attr,
                    ldap_admin_user_base_dn)
    mod_attrs = [(ldap.MOD_ADD, 'mail', str(result.email))]
    try:
        l.modify_s(user[0][0], mod_attrs)
    except Exception as error:
        logger.error(error, extra = log_extra_data(request))
        raise OkupyException('Could not modify LDAP data')
    l.unbind_s()
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
    Check if the given URL exists in the database, and if the user exists
    in the LDAP server, and afterwards try to update the user's email
    list in LDAP
    '''
    msg = ''
    result = ''
    try:
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
