# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as _login, authenticate
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.db import IntegrityError
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt

from .forms import LoginForm, SignupForm
from .models import Queue
from .openid_store import DjangoDBOpenIDStore

from ..common.exceptions import OkupyError
from ..common.ldapuser import OkupyLDAPUser
from ..common.log import log_extra_data

from edpwd import random_string
from passlib.hash import ldap_md5_crypt
import ldap.modlist as modlist
import logging

# for exceptions
from openid.server.server import (Server, ProtocolError, EncodingError,
        CheckIDRequest)
import openid.yadis.discover, openid.fetchers

logger = logging.getLogger('okupy')
logger_mail = logging.getLogger('mail_okupy')

def index(request):
    return render(request, 'index.html', {})

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
                raise OkupyError('Login failed')
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
                raise OkupyError('Login failed')
            if user.is_active:
                _login(request, user)
                request.session.set_expiry(900)
                return redirect(index)
        except OkupyError, error:
            messages.error(request, str(error))
    else:
        if request.user.is_authenticated():
            return redirect(index)
        else:
            login_form = LoginForm()
    return render(request, 'login.html', {
        'login_form': login_form,
    })

def signup(request):
    """ The signup page """
    signup_form = None
    if request.method == "POST":
        signup_form = SignupForm(request.POST)
        if signup_form.is_valid():
            try:
                if signup_form.cleaned_data['password_origin'] != signup_form.cleaned_data['password_verify']:
                    raise OkupyError("Passwords don't match")
                anon_ldap_user = OkupyLDAPUser(settings.AUTH_LDAP_BIND_DN, settings.AUTH_LDAP_BIND_PASSWORD)
                if anon_ldap_user.search_s(filterstr = signup_form.cleaned_data['username'], scope = 'onelevel'):
                    raise OkupyError('Username already exists')
                if anon_ldap_user.search_s(attr = 'mail', filterstr = signup_form.cleaned_data['email'], scope = 'onelevel'):
                    raise OkupyError('Email already exists')
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
                    raise OkupyError('Account is already pending activation')
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
                return redirect(login)
            except OkupyError, error:
                messages.error(request, str(error))
    else:
        signup_form = SignupForm()
    return render(request, 'signup.html', {
        'signup_form': signup_form,
    })

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
            except IndexError:
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
    except OkupyError, error:
        messages.error(request, str(error))
    return redirect(login)

def formerdevlist(request):
    return render(request, 'former-devlist.html', {})

def foundationlist(request):
    return render(request, 'foundation-members.html', {})

# OpenID-specific

def endpoint_url(request):
    return request.build_absolute_uri(reverse(openid_endpoint))

def get_openid_server(request):
    store = DjangoDBOpenIDStore()
    return Server(store, endpoint_url(request))

def render_openid_response(request, oresp, srv = None):
    if srv is None:
        srv = get_openid_server(request)

    try:
        eresp = srv.encodeResponse(oresp)
    except EncodingError as e:
        # XXX: do we want some different heading for it?
        return render(request, 'openid_endpoint.html',
                {
                    'error': str(e)
                }, status = 500)

    dresp = HttpResponse(eresp.body, status = eresp.code)
    for h, v in eresp.headers.items():
        dresp[h] = v

    return dresp

@csrf_exempt
def openid_endpoint(request):
    if request.method == 'POST':
        req = request.POST
    else:
        req = request.GET

    srv = get_openid_server(request)

    try:
        oreq = srv.decodeRequest(req)
    except ProtocolError as e:
        # XXX: we are supposed to send some error to the caller
        return render(request, 'openid_endpoint.html',
                {
                    'error': str(e)
                }, status = 400)

    if oreq is None:
        return render(request, 'openid_endpoint.html')

    if isinstance(oreq, CheckIDRequest):
        # immediate requests not supported yet, so immediately
        # reject them.
        if oreq.immediate:
            oresp = oreq.answer(False)
        else:
            # XXX: to be migrated
            oresp = oreq.answer(False)
#            request.session['openid_request'] = oreq
#            return redirect(auth_site)
    else:
        oresp = srv.handleRequest(oreq)

    return render_openid_response(request, oresp, srv)

def user_page(request, username):
    return render(request, 'user-page.html', {
        'endpoint_uri': endpoint_url(request)
    })
