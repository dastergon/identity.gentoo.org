# -*- coding: utf-8 -*-

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as _login, authenticate
from django.core.mail import send_mail
from django.db import IntegrityError
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from okupy.accounts.forms import LoginForm, SignupForm
from okupy.accounts.models import Queue
from okupy.common.encryption import random_string
from okupy.common.exceptions import OkupyError, LoginError, SignupError
from okupy.common.ldapuser import OkupyLDAPUser
from okupy.common.log import log_extra_data
from passlib.hash import ldap_md5_crypt
import ldap.modlist as modlist
import logging

logger = logging.getLogger('okupy')
logger_mail = logging.getLogger('mail_okupy')

def index(request):
    return render_to_response('index.html', {}, context_instance = RequestContext(request))

def login(request):
    """ The login page """
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
            """
            Perform authentication, if it retrieves a user object then
            it was successful. If it retrieves None then it failed to login
            """
            try:
                user = authenticate(username = username, password = password)
            except Exception as error:
                logger.critical(error, extra=log_extra_data(request))
                logger_mail.exception(error)
                raise OkupyError("Can't contact the LDAP server or the database")
            if not user:
                raise LoginError
            if user.is_active:
                _login(request, user)
                if not login_form.cleaned_data['remember']:
                    request.session.set_expiry(0)
                return HttpResponseRedirect('/')
        except (OkupyError, LoginError) as error:
            messages.error(request, error.value)
    else:
        if request.user.is_authenticated():
            return HttpResponseRedirect('/')
        else:
            login_form = LoginForm()
    return render_to_response('login.html', {
        'login_form': login_form,
    }, context_instance = RequestContext(request))

def signup(request):
    """ The signup page """
    signup_form = None
    if request.method == "POST":
        signup_form = SignupForm(request.POST)
        if signup_form.is_valid():
            try:
                if signup_form.cleaned_data['password_origin'] != signup_form.cleaned_data['password_verify']:
                    raise SignupError("Passwords don't match")
                anon_ldap_user = OkupyLDAPUser(settings.AUTH_LDAP_BIND_DN, settings.AUTH_LDAP_BIND_PASSWORD)
                if anon_ldap_user.search_s(filterstr = signup_form.cleaned_data['username'], scope = 'onelevel'):
                    raise SignupError('Username already exists')
                if anon_ldap_user.search_s(attr = 'mail', filterstr = signup_form.cleaned_data['email'], scope = 'onelevel'):
                    raise SignupError('Email already exists')
                anon_ldap_user.unbind_s()
                queued_user = Queue(
                    username = signup_form.cleaned_data['username'],
                    first_name = signup_form.cleaned_data['first_name'],
                    last_name = signup_form.cleaned_data['last_name'],
                    email = signup_form.cleaned_data['email'],
                    password = signup_form.cleaned_data['password_origin'],
                    token = random_string(40),
                )
                try:
                    queued_user.save()
                except IntegrityError:
                    raise SignupError('Account is already pending activation')
                except Exception as error:
                    logger.critical(error, extra=log_extra_data(request))
                    logger_mail.exception(error)
                    raise OkupyError("Can't contact the database")
                send_mail(
                    '%sAccount Activation' % settings.EMAIL_SUBJECT_PREFIX,
                    'To confirm your email address, please click the following link:\n%s' % queued_user.token,
                    '%s' % settings.SERVER_EMAIL,
                    [signup_form.cleaned_data['email']]
                )
                messages.info(request, "You will shortly receive an activation mail")
                return HttpResponseRedirect('/login/')
            except (OkupyError, SignupError) as error:
                messages.error(request, error.value)
    else:
        signup_form = SignupForm()
    return render_to_response('signup.html', {
        'signup_form': signup_form,
    }, context_instance = RequestContext(request))

def activate(request, token):
    """
    The page that users get to activate their accounts
    It is in the form /activate/$TOKEN where the token is a 40 char string
    """
    try:
        if len(token) != 40:
            raise OkupyError('Invalid URL')
        try:
            queued_user = Queue.objects.get(token=token)
        except Queue.DoesNotExist:
            raise OkupyError('Invalid URL')
        except Exception as error:
            logger.critical(error, extra=log_extra_data(request))
            logger_mail.exception(error)
            raise OkupyError("Can't contact the database")
        # add account to ldap
        admin_ldap_user = OkupyLDAPUser(settings.AUTH_LDAP_ADMIN_BIND_DN, settings.AUTH_LDAP_ADMIN_BIND_PASSWORD)
        new_user = {
            'uid': [str(queued_user.username)],
            'userPassword': [ldap_md5_crypt.encrypt(queued_user.password)],
            'mail': [str(queued_user.email)],
            'givenName': [str(queued_user.first_name)],
            'sn': [str(queued_user.last_name)],
            'gecos': ['%s %s' % (queued_user.first_name, queued_user.last_name)],
            'objectClass': settings.AUTH_LDAP_USER_OBJECTCLASS,
        }
        if 'person' in new_user['objectClass']:
            new_user['cn'] = ['%s %s' % (queued_user.first_name, queued_user.last_name)]
        if 'posixAccount' in new_user['objectClass']:
            try:
                max_uidnumber = admin_ldap_user.search_s(attr='uidNumber', scope='onelevel', attrlist=['uidNumber'])[-1][1]['uidNumber'][0]
            except TypeError:
                max_uidnumber = 0
            new_user['uidNumber'] = [str(int(max_uidnumber) + 1)]
            new_user['gidNumber'] = ['100']
            new_user['homeDirectory'] = ['/home/%s' % str(queued_user.username)]
        ldif = modlist.addModlist(new_user)
        admin_ldap_user.add_s('uid=%s,%s' % (queued_user.username, settings.AUTH_LDAP_USER_BASE_DN), ldif)
        admin_ldap_user.unbind_s()
        # remove queued account from DB
        queued_user.delete()
        messages.success(request, "Your account has been activated successfully")
    except OkupyError as error:
        messages.error(request, error.value)
    return HttpResponseRedirect('/login/')
