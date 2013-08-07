# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import (login as _login, logout as _logout,
                                 authenticate)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.db import IntegrityError
from django.forms.models import model_to_dict
from django.http import HttpResponse
from django.views.generic.base import View
from django.shortcuts import redirect, render
from django.utils.html import format_html
from django.utils.http import urlencode
from django.views.decorators.csrf import csrf_exempt

from edpwd import random_string
from openid.extensions.ax import FetchRequest, FetchResponse
from openid.extensions.sreg import SRegRequest, SRegResponse
from openid.server.server import (Server, ProtocolError, EncodingError,
                                  CheckIDRequest, ENCODE_URL,
                                  ENCODE_KVFORM, ENCODE_HTML_FORM)
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from passlib.hash import ldap_md5_crypt
from urlparse import urljoin, urlparse, parse_qsl

from .forms import LoginForm, SignupForm, SiteAuthForm
from .models import AuthToken, LDAPUser, OpenID_Attributes, Queue
from .openid_store import DjangoDBOpenIDStore
from ..common.exceptions import OkupyError
from ..common.log import log_extra_data

# the following two are for exceptions
import openid.yadis.discover
import openid.fetchers
import ldap
import ldap.modlist as modlist
import logging

logger = logging.getLogger('okupy')
logger_mail = logging.getLogger('mail_okupy')


class DevListsView(View):
    template_name = ''

    def get(self, request, *args, **kwargs):
        if 'devlist.html' in self.template_name:
            devlist = LDAPUser.objects.filter(is_developer=True)
        elif 'former-devlist.html' in self.template_name:
            devlist = LDAPUser.objects.filter(is_retired=True)
        elif 'foundation-members.html' in self.template_name:
            devlist = LDAPUser.objects.filter(is_foundation=True)
        return render(request, self.template_name, {'devlist': devlist})


@login_required
def index(request):
    anon_ldap_user = ldap.initialize(settings.AUTH_LDAP_SERVER_URI)
    results = anon_ldap_user.search_s(settings.AUTH_LDAP_USER_DN_TEMPLATE % {
        'user': request.user}, ldap.SCOPE_SUBTREE, '(uid=%s)' % (request.user))
    attrs = results[0][1]
    personal_attributes = {
        'cn': 'Real Name', 'uid': 'Nickname', 'gentooLocation': 'Location'}
    contact_attributes = {'mail': 'Email', 'gentooIM': 'IM Nickname'}
    gentoo_attributes = {
        'herd': 'Herds', 'gentooRoles': 'Roles', 'gentooJoin': 'Date Joined',
        'gentooMentor': 'Mentor', 'gentooDevBug': 'Recruitment Bug',
        'gentooRetired': 'Retired'}
    ldap_personal_info = {}
    ldap_contact_info = {}
    ldap_gentoo_info = {}

    for k, v in personal_attributes.items():
        attrs[k] = attrs.get(k, ['Empty, when it should be'])
        ldap_personal_info[v] = attrs[k][0]

    for k, v in contact_attributes.items():
        attrs[k] = attrs.get(k, [''])
        ldap_contact_info[v] = attrs[k][0]

    for k, v in gentoo_attributes.items():
        if k == 'gentooRetired' and k not in attrs:
            continue
        else:
            attrs[k] = attrs.get(k, [''])
            ldap_gentoo_info[v] = attrs[k][0]

    anon_ldap_user.unbind_s()

    return render(request, 'index.html', {
        'ldap_personal_info': ldap_personal_info,
        'ldap_contact_info': ldap_contact_info,
        'ldap_gentoo_info': ldap_gentoo_info
    })


def login(request):
    """ The login page """
    login_form = None
    user = None
    oreq = request.session.get('openid_request', None)

    if request.method == "POST" and 'cancel' in request.POST:
        if oreq is not None:
            oresp = oreq.answer(False)
            del request.session['openid_request']
            return render_openid_response(request, oresp)
        else:
            # cheat it to display the form again
            request.method = 'GET'

    if request.method == "POST":
        if 'cancel' in request.POST:
            if oreq is not None:
                oresp = oreq.answer(False)
                del request.session['openid_request']
                return render_openid_response(request, oresp)
        else:
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
                    user = authenticate(username=username, password=password)
                except Exception as error:
                    logger.critical(error, extra=log_extra_data(request))
                    logger_mail.exception(error)
                    raise OkupyError(
                        "Can't contact the LDAP server or the database")
                if not user:
                    raise OkupyError('Login failed')
                if user.is_active:
                    _login(request, user)
                    request.session.set_expiry(900)
                    return redirect(request.POST.get('next', index))
            except OkupyError as error:
                messages.error(request, str(error))
    else:
        if 'ssl_auth_success' in request.GET:
            try:
                token = AuthToken.objects.get(
                    encrypted_id=request.GET['ssl_auth_success'])
            except (AuthToken.DoesNotExist, OverflowError,
                    TypeError, ValueError):
                messages.error(request, 'Invalid SSL auth token')
            else:
                user = authenticate(username=token.user, ext_authed=True)
                token.delete()
                if user.is_active:
                    _login(request, user)
                    request.session.set_expiry(900)
                    return redirect(request.GET.get('next', index))
        elif 'ssl_auth_failed' in request.GET:
            messages.error(request, 'SSL authentication failed: %s'
                    % request.GET['ssl_auth_failed'])

        if request.user.is_authenticated():
            return redirect(request.GET.get('next', index))
        else:
            login_form = LoginForm()

    # TODO: it fails when:
    # 1. site is accessed via IP (auth.127.0.0.1),
    # 2. HTTP used on non-standard port (https://...:8000).
    ssl_auth_host = 'auth.' + request.get_host()
    current_url = request.build_absolute_uri(request.get_full_path())
    ssl_auth_path = reverse(ssl_auth) + '?' + urlencode({'back': current_url})
    ssl_auth_uri = urljoin('https://' + ssl_auth_host, ssl_auth_path)

    return render(request, 'login.html', {
        'login_form': login_form,
        'openid_request': oreq,
        'next': request.GET.get('next', index),
        'ssl_auth_uri': ssl_auth_uri,
    })


def ssl_auth(request):
    """ SSL certificate authentication. """

    ret_url = request.GET['back']
    qs = parse_qsl(urlparse(ret_url).query)

    cert_verify = request.META['SSL_CLIENT_VERIFY']
    if cert_verify == 'SUCCESS':
        cert = load_certificate(FILETYPE_PEM,
            request.META['SSL_CLIENT_RAW_CERT'])
        dn = cert.get_subject().get_components()

        # note: field may occur multiple times
        for k, v in dn:
            if k == 'emailAddress':
                try:
                    u = LDAPUser.objects.get(email__contains=v)
                except LDAPUser.DoesNotExist:
                    pass
                else:
                    auth_token = AuthToken(user=u.username)
                    auth_token.save()
                    qs.append(('ssl_auth_success',
                        auth_token.encrypted_id))
                    break
        else:
            qs.append(('ssl_auth_failed',
                'E-mail does not match any of the users'))
    else:
        if cert_verify == 'NONE':
            error = 'No certificate provided'
        else:
            error = 'Certificate verification failed'

        qs.append(('ssl_auth_failed', error))

    ret_url = urljoin(ret_url, '?' + urlencode(qs))
    return redirect(ret_url)


def logout(request):
    """ The logout page """
    _logout(request)
    return redirect(login)


def signup(request):
    """ The signup page """
    signup_form = None
    if request.method == "POST":
        signup_form = SignupForm(request.POST)
        if signup_form.is_valid():
            try:
                if signup_form.cleaned_data['password_origin'] != \
                        signup_form.cleaned_data['password_verify']:
                    raise OkupyError("Passwords don't match")
                try:
                    anon_ldap_user = ldap.initialize(
                        settings.AUTH_LDAP_SERVER_URI)
                    anon_ldap_user.simple_bind_s(
                        settings.AUTH_LDAP_BIND_DN,
                        settings.AUTH_LDAP_BIND_PASSWORD)
                except Exception as error:
                    logger.critical(error, extra=log_extra_data(request))
                    logger_mail.exception(error)
                    raise OkupyError("Can't contact LDAP server")
                if anon_ldap_user.search_s(
                        settings.AUTH_LDAP_USER_BASE_DN, ldap.SCOPE_ONELEVEL,
                        filterstr='(uid=%s)' %
                        signup_form.cleaned_data['username']):
                    raise OkupyError('Username already exists')
                if anon_ldap_user.search_s(
                        settings.AUTH_LDAP_USER_BASE_DN, ldap.SCOPE_ONELEVEL,
                        filterstr='(mail=%s)' %
                        signup_form.cleaned_data['email']):
                    raise OkupyError('Email already exists')
                anon_ldap_user.unbind_s()
                queued_user = Queue(
                    username=signup_form.cleaned_data['username'],
                    first_name=signup_form.cleaned_data['first_name'],
                    last_name=signup_form.cleaned_data['last_name'],
                    email=signup_form.cleaned_data['email'],
                    password=signup_form.cleaned_data['password_origin'],
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
                    'To confirm your email address, please click the \
                    following link:\n%s' % queued_user.encrypted_id,
                    '%s' % settings.SERVER_EMAIL,
                    [signup_form.cleaned_data['email']]
                )
                messages.info(
                    request, "You will shortly receive an activation mail")
                return redirect(login)
            except OkupyError as error:
                messages.error(request, str(error))
    else:
        signup_form = SignupForm()
    return render(request, 'signup.html', {
        'signup_form': signup_form,
    })


def activate(request, token):
    """
    The page that users get to activate their accounts
    It is in the form /activate/$TOKEN
    """
    try:
        try:
            queued_user = Queue.objects.get(encrypted_id=token)
        except (Queue.DoesNotExist, OverflowError, TypeError, ValueError):
            raise OkupyError('Invalid URL')
        except Exception as error:
            logger.critical(error, extra=log_extra_data(request))
            logger_mail.exception(error)
            raise OkupyError("Can't contact the database")
        # add account to ldap
        try:
            admin_ldap_user = ldap.initialize(settings.AUTH_LDAP_SERVER_URI)
            admin_ldap_user.simple_bind_s(
                settings.AUTH_LDAP_ADMIN_BIND_DN,
                settings.AUTH_LDAP_ADMIN_BIND_PASSWORD)
        except Exception as error:
            logger.critical(error, extra=log_extra_data(request))
            logger_mail.exception(error)
            raise OkupyError("Can't contact LDAP server")
        new_user = {
            'uid': [str(queued_user.username)],
            'userPassword': [ldap_md5_crypt.encrypt(queued_user.password)],
            'mail': [str(queued_user.email)],
            'givenName': [str(queued_user.first_name)],
            'sn': [str(queued_user.last_name)],
            'gecos': ['%s %s' % (queued_user.first_name,
                                 queued_user.last_name)],
            'objectClass': settings.AUTH_LDAP_USER_OBJECTCLASS,
        }
        if 'person' in new_user['objectClass']:
            new_user['cn'] = ['%s %s' % (
                queued_user.first_name, queued_user.last_name)]
        if 'posixAccount' in new_user['objectClass']:
            try:
                results = admin_ldap_user.search_s(
                    settings.AUTH_LDAP_USER_BASE_DN, ldap.SCOPE_ONELEVEL,
                    '(uidNumber=*)', ['uidNumber'])
                uidnumbers = [int(x[1]['uidNumber'][0]) for x in results]
                max_uidnumber = max(uidnumbers)
            except (IndexError, ValueError):
                max_uidnumber = 0
            new_user['uidNumber'] = [str(max_uidnumber + 1)]
            new_user['gidNumber'] = ['100']
            new_user['homeDirectory'] = [
                '/home/%s' % str(queued_user.username)]
        ldif = modlist.addModlist(new_user)
        admin_ldap_user.add_s('uid=%s,%s' % (
            queued_user.username, settings.AUTH_LDAP_USER_BASE_DN), ldif)
        admin_ldap_user.unbind_s()
        # remove queued account from DB
        queued_user.delete()
        messages.success(
            request, "Your account has been activated successfully")
    except OkupyError as error:
        messages.error(request, str(error))
    return redirect(login)


# OpenID-specific


def endpoint_url(request):
    return request.build_absolute_uri(reverse(openid_endpoint))


def get_openid_server(request):
    store = DjangoDBOpenIDStore()
    return Server(store, endpoint_url(request))


def render_openid_response(request, oresp, srv=None):
    if srv is None:
        srv = get_openid_server(request)

    try:
        eresp = srv.encodeResponse(oresp)
    except EncodingError as e:
        # TODO: do we want some different heading for it?
        return render(request, 'openid_endpoint.html', {
            'error': str(e),
        }, status=500)

    dresp = HttpResponse(eresp.body, status=eresp.code)
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
        if e.whichEncoding() == ENCODE_URL:
            return redirect(e.encodeToURL())
        elif e.whichEncoding() == ENCODE_HTML_FORM:
            return HttpResponse(e.toHTML())
        elif e.whichEncoding() == ENCODE_KVFORM:
            return HttpResponse(e.encodeToKVForm(), status=400)
        else:
            return render(request, 'openid_endpoint.html', {
                'error': str(e)
            }, status=400)

    if oreq is None:
        return render(request, 'openid_endpoint.html')

    if isinstance(oreq, CheckIDRequest):
        # immediate requests not supported yet, so immediately
        # reject them.
        if oreq.immediate:
            oresp = oreq.answer(False)
        else:
            request.session['openid_request'] = oreq
            return redirect(openid_auth_site)
    else:
        oresp = srv.handleRequest(oreq)

    return render_openid_response(request, oresp, srv)


def user_page(request, username):
    return render(request, 'user-page.html', {
        'endpoint_uri': endpoint_url(request),
    })


openid_ax_attribute_mapping = {
    # http://web.archive.org/web/20110714025426/http://www.axschema.org/types/
    'http://axschema.org/namePerson/friendly': 'nickname',
    'http://axschema.org/contact/email': 'email',
    'http://axschema.org/namePerson': 'fullname',
    'http://axschema.org/birthDate': 'dob',
    'http://axschema.org/person/gender': 'gender',
    'http://axschema.org/contact/postalCode/home': 'postcode',
    'http://axschema.org/contact/country/home': 'country',
    'http://axschema.org/pref/language': 'language',
    'http://axschema.org/pref/timezone': 'timezone',

    # TODO: provide further attributes
}


@login_required
def openid_auth_site(request):
    try:
        oreq = request.session['openid_request']
    except KeyError:
        return render(request, 'openid-auth-site.html', {
            'error': 'No OpenID request associated. The request may have \
            expired.',
        }, status=400)

    sreg = SRegRequest.fromOpenIDRequest(oreq)
    ax = FetchRequest.fromOpenIDRequest(oreq)

    sreg_fields = set(sreg.allRequestedFields())
    if ax:
        for uri in ax.requested_attributes:
            k = openid_ax_attribute_mapping.get(uri)
            if k:
                sreg_fields.add(k)

    ldap_user = LDAPUser.objects.get(username=request.user.username)
    if sreg_fields:
        sreg_data = {
            'nickname': ldap_user.username,
            'email': ldap_user.email,
            'fullname': ldap_user.full_name,
            'dob': ldap_user.birthday,
        }

        for k in list(sreg_data):
            if not sreg_data[k]:
                del sreg_data[k]
    else:
        sreg_data = {}
    sreg_fields = sreg_data.keys()

    # Read preferences from the db.
    try:
        saved_pref = OpenID_Attributes.objects.get(
            uid=ldap_user.uid,
            trust_root=oreq.trust_root,
        )
    except OpenID_Attributes.DoesNotExist:
        saved_pref = None
        auto_auth = False
    else:
        auto_auth = saved_pref.always_auth

    if auto_auth or request.POST:
        if auto_auth:
            # TODO: can we do this nicer?
            form_inp = model_to_dict(saved_pref)
        else:
            form_inp = request.POST
        form = SiteAuthForm(form_inp, instance=saved_pref)
        # can it be invalid somehow?
        assert(form.is_valid())
        attrs = form.save(commit=False)

        # nullify fields that were not requested
        for fn in form.cleaned_data:
            if fn in ('always_auth',):
                pass
            elif hasattr(attrs, fn) and fn not in sreg_fields:
                setattr(attrs, fn, None)

        if auto_auth or 'accept' in request.POST:
            # prepare sreg response
            for fn, send in form.cleaned_data.items():
                if fn not in sreg_data:
                    pass
                elif not send:
                    del sreg_data[fn]
                elif isinstance(sreg_data[fn], list):
                    form_key = 'which_%s' % fn
                    val = form.cleaned_data[form_key]
                    if val not in sreg_data[fn]:
                        raise NotImplementedError(
                            'Changing choices not implemented yet')
                    sreg_data[fn] = val
                    if not auto_auth:
                        setattr(attrs, form_key, val)

            if not auto_auth:
                # save prefs in the db
                # (if auto_auth, then nothing changed)
                attrs.uid = ldap_user.uid
                attrs.trust_root = oreq.trust_root
                attrs.save()

            oresp = oreq.answer(True, identity=request.build_absolute_uri(
                reverse(user_page, args=(request.user.username,))))

            sreg_resp = SRegResponse.extractResponse(sreg, sreg_data)
            oresp.addExtension(sreg_resp)

            if ax:
                ax_resp = FetchResponse(ax)
                for uri in ax.requested_attributes:
                    k = openid_ax_attribute_mapping.get(uri)
                    if k and k in sreg_data:
                        ax_resp.addValue(uri, sreg_data[k])
                oresp.addExtension(ax_resp)
        elif 'reject' in request.POST:
            oresp = oreq.answer(False)
        else:
            return render(request, 'openid-auth-site.html', {
                'error': 'Invalid request submitted.',
            }, status=400)

        del request.session['openid_request']
        return render_openid_response(request, oresp)

    form = SiteAuthForm(instance=saved_pref)
    sreg_form = {}
    # Fill in lists for choices
    for f in sreg_fields:
        if f not in sreg_data:
            pass
        elif isinstance(sreg_data[f], list):
            form.fields['which_%s' % f].widget.choices = [
                (x, x) for x in sreg_data[f]
            ]
            sreg_form[f] = form['which_%s' % f]
        else:
            sreg_form[f] = format_html("<input type='text'"
                                       + " readonly='readonly'"
                                       + " value='{0}' />",
                                       sreg_data[f])

    try:
        # TODO: cache it
        if oreq.returnToVerified():
            tr_valid = 'Return-To valid and trusted'
        else:
            tr_valid = 'Return-To untrusted'
    except openid.yadis.discover.DiscoveryFailure:
        tr_valid = 'Unable to verify trust (Yadis unsupported)'
    except openid.fetchers.HTTPFetchingError:
        tr_valid = 'Unable to verify trust (HTTP error)'

    return render(request, 'openid-auth-site.html', {
        'openid_request': oreq,
        'return_to_valid': tr_valid,
        'form': form,
        'sreg': sreg_fields,
        'sreg_form': sreg_form,
        'policy_url': sreg.policy_url,
    })
