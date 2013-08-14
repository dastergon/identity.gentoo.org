# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import (login as _login, logout as _logout,
                                 authenticate)
from django.contrib.sessions.backends.cache import SessionStore
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.db import IntegrityError
from django.forms.models import model_to_dict
from django.http import (HttpResponse, HttpResponseForbidden,
                         HttpResponseBadRequest)
from django.views.generic.base import View
from django.shortcuts import redirect, render
from django.utils.html import format_html
from django.utils.http import urlencode
from django.views.decorators.csrf import csrf_exempt
from django_otp.decorators import otp_required

from openid.extensions.ax import FetchRequest, FetchResponse
from openid.extensions.sreg import SRegRequest, SRegResponse
from openid.server.server import (Server, ProtocolError, EncodingError,
                                  CheckIDRequest, ENCODE_URL,
                                  ENCODE_KVFORM, ENCODE_HTML_FORM)
from passlib.hash import ldap_md5_crypt
from urlparse import urljoin, urlparse, parse_qsl

from .forms import (LoginForm, OpenIDLoginForm, SSLCertLoginForm,
                    OTPForm, SignupForm, SiteAuthForm)
from .models import LDAPUser, OpenID_Attributes, Queue
from .openid_store import DjangoDBOpenIDStore
from ..common.ldap_helpers import get_ldap_connection
from ..common.crypto import cipher
from ..common.exceptions import OkupyError
from ..common.log import log_extra_data
from ..otp import init_otp
from ..otp.sotp.models import SOTPDevice
from ..otp.totp.models import TOTPDevice

# the following two are for exceptions
import openid.yadis.discover
import openid.fetchers
import base64
import django_otp
import io
import ldap
import ldap.modlist as modlist
import logging
import qrcode

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


@otp_required
def index(request):
    ldb_user = LDAPUser.objects.filter(username=request.user.username)
    return render(request, 'index.html', {
        'ldb_user': ldb_user
    })


def login(request):
    """ The login page """
    user = None
    oreq = request.session.get('openid_request', None)
    # this can be POST or GET, and can be null or empty
    next = request.REQUEST.get('next') or reverse(index)
    is_otp = False
    login_form = None
    login_form_class = OpenIDLoginForm if oreq else LoginForm

    try:
        if request.method != 'POST':
            pass
        elif 'cancel' in request.POST:
            # note: this wipes request.session
            _logout(request)
            if oreq is not None:
                oresp = oreq.answer(False)
                return render_openid_response(request, oresp)
        elif 'otp_token' in request.POST:
            # if user's not authenticated, go back to square one
            if not request.user.is_authenticated():
                raise OkupyError('OTP verification timed out')

            is_otp = True
            otp_form = OTPForm(request.POST)
            if otp_form.is_valid():
                token = otp_form.cleaned_data['otp_token']
            else:
                raise OkupyError('OTP verification failed')

            dev = django_otp.match_token(request.user, token)
            if not dev:
                raise OkupyError('OTP verification failed')
            django_otp.login(request, dev)
        else:
            login_form = login_form_class(request.POST)
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

            if oreq:
                request.session['auto_logout'] = (
                    login_form.cleaned_data['auto_logout'])
    except OkupyError as error:
        messages.error(request, str(error))

    if user and user.is_active:
        _login(request, user)
        # prepare devices, and see if OTP is enabled
        init_otp(request)
    if request.user.is_authenticated():
        if request.user.is_verified():
            return redirect(next)
        login_form = OTPForm()
        is_otp = True
    if login_form is None:
        login_form = login_form_class()

    if is_otp:
        ssl_auth_form = None
        ssl_auth_uri = None
    else:
        if 'encrypted_id' not in request.session:
            # .cache_key is a very good property since it ensures
            # that the cache is actually created, and works from first
            # request
            session_id = request.session.cache_key

            # since it always starts with the backend module name
            # and __init__() expects pure id, we can strip that
            assert(session_id.startswith('django.contrib.sessions.cache'))
            session_id = session_id[29:]
            request.session['encrypted_id'] = base64.b64encode(
                cipher.encrypt(session_id))

        # TODO: it fails when:
        # 1. site is accessed via IP (auth.127.0.0.1),
        # 2. HTTP used on non-standard port (https://...:8000).
        ssl_auth_form = SSLCertLoginForm({
            'session_id': request.session['encrypted_id'],
            'next': request.build_absolute_uri(next),
            'login_uri': request.build_absolute_uri(request.get_full_path()),
        })

        ssl_auth_host = 'auth.' + request.get_host()
        ssl_auth_path = reverse(ssl_auth)
        ssl_auth_uri = urljoin('https://' + ssl_auth_host, ssl_auth_path)

    return render(request, 'login.html', {
        'login_form': login_form,
        'openid_request': oreq,
        'next': next,
        'ssl_auth_uri': ssl_auth_uri,
        'ssl_auth_form': ssl_auth_form,
        'is_otp': is_otp,
    })


@csrf_exempt
def ssl_auth(request):
    """ SSL certificate authentication. """

    if request.method != 'POST':
        # TODO: add some unicorns?
        return HttpResponseBadRequest('400 Bad Request')

    ssl_auth_form = SSLCertLoginForm(request.POST)
    if not ssl_auth_form.is_valid():
        return HttpResponseBadRequest('400 Bad Request')

    session_id = cipher.decrypt(
            base64.b64decode(ssl_auth_form.cleaned_data['session_id']),
            32)

    next_uri = ssl_auth_form.cleaned_data['login_uri']

    user = authenticate(request=request)
    if user and user.is_active:
        _login(request, user)
        init_otp(request)
        if request.user.is_verified(): # OTP disabled
            next_uri = ssl_auth_form.cleaned_data['next']
    else:
        messages.error(request, 'Certificate authentication failed')

    # so, django will always start a new session for us. we need to copy
    # the data to the original session and preferably flush the new one.
    session = SessionStore(session_key=session_id)
    session.update(request.session)
    session.save()
    request.session.flush()
    return redirect(next_uri)


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
                    anon_ldap_user = get_ldap_connection()
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
            admin_ldap_user = get_ldap_connection(admin=True)
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


@otp_required
def otp_setup(request):
    dev = TOTPDevice.objects.get(user=request.user)
    secret = None
    conf_form = None
    skeys = None

    if request.method == 'POST':
        if 'disable' in request.POST:
            dev.disable()
        elif 'confirm' in request.POST and 'otp_secret' in request.session:
            secret = request.session['otp_secret']
            conf_form = OTPForm(request.POST)
            try:
                if not conf_form.is_valid():
                    raise OkupyError()
                token = conf_form.cleaned_data['otp_token']
                if not dev.verify_token(token, secret):
                    raise OkupyError()
            except OkupyError:
                messages.error(request, 'Token verification failed.')
                conf_form = OTPForm()
            else:
                dev.enable(secret)
                secret = None
                conf_form = None
                sdev = SOTPDevice.objects.get(user=request.user)
                skeys = sdev.gen_keys()
                messages.info(request, 'The new secret has been set.')
        elif 'enable' in request.POST:
            secret = dev.gen_secret()
            request.session['otp_secret'] = secret
            conf_form = OTPForm()
        elif 'recovery' in request.POST:
            sdev = SOTPDevice.objects.get(user=request.user)
            skeys = sdev.gen_keys()
            messages.info(request, 'Your old recovery keys have been revoked.')
        elif 'cancel' in request.POST:
            messages.info(request, 'Secret change aborted. Previous settings are in effect.')

    if secret:
        # into groups of four characters
        secret = ' '.join([secret[i:i+4]
                           for i in range(0, len(secret), 4)])
    if skeys:
        # xxx xx xxx
        def group_key(k):
            s = str(k)
            return ' '.join([s[0:3], s[3:5], s[5:8]])
        skeys = list([group_key(k) for k in skeys])

    return render(request, 'otp-setup.html', {
        'otp_enabled': dev.is_enabled(),
        'secret': secret,
        'conf_form': conf_form,
        'skeys': skeys,
    })


def otp_qrcode(request):
    dev = TOTPDevice()
    secret = request.session.get('otp_secret')
    if not secret:
        return HttpResponseForbidden()

    qr = qrcode.make(dev.get_uri(secret), box_size=5)
    f = io.BytesIO()
    qr.save(f, 'PNG')

    return HttpResponse(f.getvalue(), content_type='image/png')


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


@otp_required
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

        if request.session.get('auto_logout', False):
            # _logout clears request.session
            _logout(request)
        else:
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
