# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import (login as _login, logout as _logout,
                                 authenticate)
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.db import IntegrityError
from django.forms.models import model_to_dict
from django.http import (HttpResponse, HttpResponseForbidden,
                         HttpResponseBadRequest)
from django.views.decorators.cache import cache_page
from django.shortcuts import redirect, render
from django.utils.html import format_html
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django_otp.decorators import otp_required

from openid.extensions.ax import FetchRequest, FetchResponse
from openid.extensions.sreg import SRegRequest, SRegResponse
from openid.server.server import (Server, ProtocolError, EncodingError,
                                  CheckIDRequest, ENCODE_URL,
                                  ENCODE_KVFORM, ENCODE_HTML_FORM)
from passlib.hash import ldap_md5_crypt
from urlparse import urljoin

from okupy import OkupyError
from okupy.accounts.forms import (LoginForm, OpenIDLoginForm, SSLCertLoginForm,
                                  OTPForm, SignupForm, SiteAuthForm,
                                  StrongAuthForm, ProfileSettingsForm,
                                  ContactSettingsForm, EmailSettingsForm,
                                  GentooAccountSettingsForm,
                                  PasswordSettingsForm)
from okupy.accounts.models import LDAPUser, OpenID_Attributes, Queue
from okupy.accounts.openid_store import DjangoDBOpenIDStore
from okupy.common.ldap_helpers import (get_bound_ldapuser,
                                       set_secondary_password,
                                       remove_secondary_password)
from okupy.common.decorators import strong_auth_required, anonymous_required
from okupy.common.log import log_extra_data
from okupy.crypto.ciphers import sessionrefcipher
from okupy.crypto.models import RevokedToken
from okupy.otp import init_otp
from okupy.otp.sotp.models import SOTPDevice
from okupy.otp.totp.models import TOTPDevice

# the following two are for exceptions
import openid.yadis.discover
import openid.fetchers
import django_otp
import hashlib
import io
import ldap
import logging
import qrcode

logger = logging.getLogger('okupy')
logger_mail = logging.getLogger('mail_okupy')


@cache_page(60 * 20)
def lists(request, acc_list):
    devlist = LDAPUser.objects.all()
    if acc_list == 'devlist':
        devlist = devlist.filter(is_developer=True)
    elif acc_list == 'former-devlist':
        devlist = devlist.filter(is_retired=True)
    elif acc_list == 'foundation-members':
        devlist = devlist.filter(is_foundation=True)
    return render(request, '%s.html' % acc_list, {'devlist': devlist})


@otp_required
def index(request):
    ldb_user = LDAPUser.objects.filter(username=request.user.username)
    return render(request, 'index.html', {
        'ldb_user': ldb_user,
    })


def login(request):
    """ The login page """
    user = None
    oreq = request.session.get('openid_request', None)
    # this can be POST or GET, and can be null or empty
    next = request.REQUEST.get('next') or reverse(index)
    is_otp = False
    login_form = None
    strong_auth_req = 'strong_auth_requested' in request.session

    if oreq:
        login_form_class = OpenIDLoginForm
    elif ('strong_auth_requested' in request.session
            and request.user.is_authenticated()):
        login_form_class = StrongAuthForm
    else:
        login_form_class = LoginForm

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

            # prevent replay attacks and race conditions
            if not RevokedToken.add(token, request.user):
                raise OkupyError('OTP verification failed')
            dev = django_otp.match_token(request.user, token)
            if not dev:
                raise OkupyError('OTP verification failed')
            django_otp.login(request, dev)
        else:
            login_form = login_form_class(request.POST)
            if login_form.is_valid():
                if login_form_class != StrongAuthForm:
                    username = login_form.cleaned_data['username']
                else:
                    username = request.user.username
                password = login_form.cleaned_data['password']
            else:
                raise OkupyError('Login failed')
            """
            Perform authentication, if it retrieves a user object then
            it was successful. If it retrieves None then it failed to login
            """
            try:
                user = authenticate(
                    request=request,
                    username=username,
                    password=password)
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
        set_secondary_password(request=request, password=password)
    if request.user.is_authenticated():
        if (strong_auth_req
                and not 'secondary_password' in request.session):
            if request.method != 'POST':
                messages.info(request, 'You need to type in your password'
                              + ' again to perform this action')
        else:
            if request.user.is_verified():
                return redirect(next)
            login_form = OTPForm()
            is_otp = True
    if login_form is None:
        login_form = login_form_class()

    if is_otp or strong_auth_req:
        ssl_auth_form = None
        ssl_auth_uri = None
        ssh_auth_command = None
    else:
        encrypted_id = sessionrefcipher.encrypt(request.session)

        # TODO: it fails when:
        # 1. site is accessed via IP (auth.127.0.0.1),
        # 2. HTTP used on non-standard port (https://...:8000).
        ssl_auth_form = SSLCertLoginForm({
            'session': encrypted_id,
            'next': request.build_absolute_uri(next),
            'login_uri': request.build_absolute_uri(request.get_full_path()),
        })

        ssl_auth_host = 'auth.' + request.get_host()
        ssl_auth_path = reverse(ssl_auth)
        ssl_auth_uri = urljoin('https://' + ssl_auth_host, ssl_auth_path)

        if settings.SSH_BIND[1] == 22:
            ssh_port_opt = ''
        else:
            ssh_port_opt = '-p %d ' % settings.SSH_BIND[1]

        ssh_auth_command = 'ssh %sauth+%s@%s' % (
            ssh_port_opt,
            encrypted_id,
            request.get_host().split(':')[0])

    return render(request, 'login.html', {
        'login_form': login_form,
        'openid_request': oreq,
        'next': next,
        'ssl_auth_uri': ssl_auth_uri,
        'ssl_auth_form': ssl_auth_form,
        'ssh_auth_command': ssh_auth_command,
        'is_otp': is_otp,
    })


@csrf_exempt
@require_POST
def ssl_auth(request):
    """ SSL certificate authentication. """

    ssl_auth_form = SSLCertLoginForm(request.POST)
    if not ssl_auth_form.is_valid():
        return HttpResponseBadRequest('400 Bad Request')

    session = ssl_auth_form.cleaned_data['session']
    next_uri = ssl_auth_form.cleaned_data['login_uri']

    user = authenticate(request=request)
    if user and user.is_active:
        _login(request, user)
        init_otp(request)
        if request.user.is_verified():  # OTP disabled
            next_uri = ssl_auth_form.cleaned_data['next']
    else:
        messages.error(request, 'Certificate authentication failed')

    # so, django will always start a new session for us. we need to copy
    # the data to the original session and preferably flush the new one.
    session.update(request.session)

    # always logout automatically from SSL-based auth
    # it's easy enough to log back in anyway
    if 'openid_request' in session:
        session['auto_logout'] = True

    session.save()
    request.session.flush()
    return redirect(next_uri)


def logout(request):
    """ The logout page """
    try:
        remove_secondary_password(request)
    except Exception as error:
        logger.critical(error, extra=log_extra_data(request))
        logger_mail.exception(error)
    finally:
        _logout(request)
    return redirect(login)


@anonymous_required
def signup(request):
    """ The signup page """
    signup_form = None
    if request.method == "POST":
        signup_form = SignupForm(request.POST)
        if signup_form.is_valid():
            try:
                try:
                    LDAPUser.objects.get(
                        username=signup_form.cleaned_data['username'])
                except LDAPUser.DoesNotExist:
                    pass
                except Exception as error:
                    logger.critical(error, extra=log_extra_data(request))
                    logger_mail.exception(error)
                    raise OkupyError("Can't contact LDAP server")
                else:
                    raise OkupyError('Username already exists')
                try:
                    LDAPUser.objects.get(
                        email__contains=signup_form.cleaned_data['email'])
                except LDAPUser.DoesNotExist:
                    pass
                else:
                    raise OkupyError('Email already exists')
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


@anonymous_required
def activate(request, token):
    """
    The page that users get to activate their accounts
    It is in the form /activate/$TOKEN
    """
    try:
        try:
            queued = Queue.objects.get(encrypted_id=token)
        except (Queue.DoesNotExist, OverflowError, TypeError, ValueError):
            raise OkupyError('Invalid URL')
        except Exception as error:
            logger.critical(error, extra=log_extra_data(request))
            logger_mail.exception(error)
            raise OkupyError("Can't contact the database")
        # get max uidNumber
        try:
            uidnumber = LDAPUser.objects.latest('uid').uid + 1
        except LDAPUser.DoesNotExist:
            uidnumber = 1
        except Exception as error:
            logger.critical(error, extra=log_extra_data(request))
            logger_mail.exception(error)
            raise OkupyError("Can't contact LDAP server")
        # add account to ldap
        new_user = LDAPUser(
            object_class=settings.AUTH_LDAP_USER_OBJECTCLASS,
            last_name=queued.last_name,
            full_name='%s %s' % (queued.first_name, queued.last_name),
            password=[ldap_md5_crypt.encrypt(queued.password)],
            first_name=queued.first_name,
            email=[queued.email],
            username=queued.username,
            uid=uidnumber,
            gid=100,
            gecos='%s %s' % (queued.first_name, queued.last_name),
            home_directory='/home/%s' % queued.username,
            ACL=['user.group'],
        )
        new_user.save()
        # remove queued account from DB
        queued.delete()
        messages.success(
            request, "Your account has been activated successfully")
    except OkupyError as error:
        messages.error(request, str(error))
    return redirect(login)


# Settings

@strong_auth_required
@otp_required
def profile_settings(request):
    """ Primary account settings, """
    with get_bound_ldapuser(request) as user_info:
        profile_settings = None
        if request.method == "POST":
            profile_settings = ProfileSettingsForm(request.POST)
            if profile_settings.is_valid():
                try:
                    #birthday = profile_settings.cleaned_data['birthday']
                    first_name = profile_settings.cleaned_data['first_name']
                    last_name = profile_settings.cleaned_data['last_name']

                    if user_info.first_name != first_name:
                        user_info.first_name = first_name

                    if user_info.last_name != last_name:
                        user_info.last_name = last_name

                    user_info.full_name = '%s %s' % (first_name, last_name)
                    user_info.gecos = '%s %s' % (first_name, last_name)

                    """
                    if user_info.birthday != birthday:
                        user_info.birthday = birthday
                    """
                    try:
                        user_info.save()
                    except IntegrityError:
                        pass
                except ldap.TYPE_OR_VALUE_EXISTS:
                    pass
                except Exception as error:
                    logger.critical(error, extra=log_extra_data(request))
                    logger_mail.exception(error)
                    raise OkupyError("Can't contact LDAP server")
        else:
            profile_settings = ProfileSettingsForm()

        return render(request, 'settings-profile.html', {
            'profile_settings': profile_settings,
            'user_info': user_info,
        })


@strong_auth_required
@otp_required
def password_settings(request):
    """ Password settings """
    with get_bound_ldapuser(request) as user_info:
        password_settings = None
        if request.method == "POST":
            password_settings = PasswordSettingsForm(request.POST)
            if password_settings.is_valid():
                try:
                    new_password = password_settings.cleaned_data[
                        'new_password']
                    new_password_verify = password_settings.cleaned_data[
                        'new_password_verify']
                    old_password = password_settings.cleaned_data[
                        'old_password']

                    if old_password and (new_password == new_password_verify):
                        for hash in list(user_info.password):
                            print hash
                            try:
                                if ldap_md5_crypt.verify(old_password, hash):
                                    user_info.password.append(
                                        ldap_md5_crypt.encrypt(
                                            new_password_verify))
                                    user_info.password.remove(hash)
                                    break
                            except ValueError:
                                # ignore unknown hashes
                                pass
                    try:
                        user_info.save()
                    except IntegrityError:
                        pass
                except ldap.TYPE_OR_VALUE_EXISTS:
                    pass
                except Exception as error:
                    logger.critical(error, extra=log_extra_data(request))
                    logger_mail.exception(error)
                    raise OkupyError("Can't contact LDAP server")
        else:
            password_settings = PasswordSettingsForm()

        return render(request, 'settings-password.html', {
            'password_settings': password_settings,
            'user_info': user_info,
        })


@strong_auth_required
@otp_required
def email_settings(request):
    """ Email Settings """
    with get_bound_ldapuser(request) as user_info:
        email_settings = None
        if request.method == "POST":
            email_settings = EmailSettingsForm(request.POST)
            if email_settings.is_valid():
                try:
                    email = email_settings.cleaned_data['email']
                    gravatar_mail = email_settings.cleaned_data['gravatar']

                    if request.POST.get('delete'):
                        user_info.email.remove(email)
                    else:
                        user_info.email.append(email)

                    if gravatar_mail:
                        gravatar_hash = hashlib.md5(gravatar_mail).hexdigest()
                        user_info.gravatar = gravatar_hash

                    try:
                        user_info.save()
                    except IntegrityError:
                        pass
                except ldap.TYPE_OR_VALUE_EXISTS:
                    pass
                except Exception as error:
                    logger.critical(error, extra=log_extra_data(request))
                    logger_mail.exception(error)
                    raise OkupyError("Can't contact LDAP server")
        else:
            email_settings = EmailSettingsForm()

        return render(request, 'settings-email.html', {
            'email_settings': email_settings,
            'user_info': user_info,
        })


@strong_auth_required
@otp_required
def contact_settings(request):
    """ Contact details """
    with get_bound_ldapuser(request) as user_info:
        contact_settings = None
        if request.method == "POST":
            contact_settings = ContactSettingsForm(request.POST)
            if contact_settings.is_valid():
                try:
                    gpg_fingerprint = contact_settings.cleaned_data[
                        'gpg_fingerprint']
                    im = contact_settings.cleaned_data['im']
                    latitude = contact_settings.cleaned_data['latitude']
                    location = contact_settings.cleaned_data['location']
                    longitude = contact_settings.cleaned_data['longitude']
                    phone = contact_settings.cleaned_data['phone']
                    website = contact_settings.cleaned_data['website']

                    if location and user_info.location != location:
                        user_info.location = location

                    if user_info.phone != phone:
                        user_info.phone = phone

                    if request.POST.get('delete_web'):
                        user_info.website.remove(website)
                    elif website and (not website in user_info.website):
                        user_info.website.append(website)

                    if request.POST.get('delete_im'):
                        user_info.im.remove(im)
                    elif im and (not im in user_info.im):
                        user_info.im.append(im)

                    if user_info.longitude != longitude:
                        user_info.longitude = longitude

                    if user_info.latitude != latitude:
                        user_info.latitude = latitude

                    if request.POST.get('delete_gpg'):
                        user_info.gpg_fingerprint.remove(gpg_fingerprint)
                    elif gpg_fingerprint and \
                            (not gpg_fingerprint in user_info.gpg_fingerprint):
                        user_info.gpg_fingerprint.append(gpg_fingerprint)

                    try:
                        user_info.save()
                    except IntegrityError:
                        pass
                except ldap.TYPE_OR_VALUE_EXISTS:
                    pass
                except Exception as error:
                    logger.critical(error, extra=log_extra_data(request))
                    logger_mail.exception(error)
                    raise OkupyError("Can't contact LDAP server")
        else:
            contact_settings = ContactSettingsForm()

        return render(request, 'settings-contact.html', {
            'contact_settings': contact_settings,
            'user_info': user_info,
        })


@strong_auth_required
@otp_required
def gentoo_dev_settings(request):
    """ Gentoo related information """
    with get_bound_ldapuser(request) as user_info:
        gentoo_account_settings = None
        if request.method == "POST":
            gentoo_account_settings = GentooAccountSettingsForm(request.POST)
            if gentoo_account_settings.is_valid():
                try:
                    devbug = gentoo_account_settings.cleaned_data[
                        'developer_bug']
                    gentoo_join_date = gentoo_account_settings.cleaned_data[
                        'gentoo_join_date']
                    gentoo_mentor = gentoo_account_settings.cleaned_data[
                        'mentor']
                    gentoo_retire_date = gentoo_account_settings.cleaned_data[
                        'gentoo_retire_date']
                    gentoo_mentor = gentoo_account_settings.cleaned_data[
                        'mentor']
                    planet_feed = gentoo_account_settings.cleaned_data[
                        'planet_feed']
                    universe_feed = gentoo_account_settings.cleaned_data[
                        'universe_feed']

                    if request.POST.get('delete_devbug'):
                        user_info.devbug.remove(devbug)
                    elif devbug and (not devbug in user_info.developer_bug):
                        user_info.developer_bug.append(devbug)

                    if request.POST.get('delete_gjd'):
                        user_info.gentoo_join_date.remove(gentoo_join_date)
                    elif gentoo_join_date and (not gentoo_join_date in user_info.gentoo_join_date):
                        user_info.gentoo_join_date.append(gentoo_join_date)

                    if request.POST.get('delete_mentor'):
                        user_info.mentor.remove(gentoo_mentor)
                    elif gentoo_mentor and \
                            (not gentoo_mentor in user_info.mentor):
                        user_info.mentor.append(gentoo_mentor)

                    if user_info.gentoo_retire_date:
                        if request.POST.get('delete_grd'):
                            user_info.gentoo_retire_date.remove(gentoo_retire_date)
                        elif gentoo_retire_date and (not gentoo_retire_date in user_info.gentoo_retire_date):
                            user_info.gentoo_retire_date.append(gentoo_retire_date)

                    if user_info.planet_feed != planet_feed:
                        user_info.planet_feed = planet_feed

                    if user_info.universe_feed != universe_feed:
                        user_info.universe_feed = universe_feed

                    try:
                        user_info.save()
                    except IntegrityError:
                        pass
                except ldap.TYPE_OR_VALUE_EXISTS:
                    pass
                except Exception as error:
                    logger.critical(error, extra=log_extra_data(request))
                    logger_mail.exception(error)
                    raise OkupyError("Can't contact LDAP server")
        else:
            gentoo_account_settings = GentooAccountSettingsForm()

        return render(request, 'settings-gentoo.html', {
            'gentoo_account_settings': gentoo_account_settings,
            'user_info': user_info,
        })


@strong_auth_required
@otp_required
def otp_setup(request):
    dev = TOTPDevice.objects.get(user=request.user)
    secret = None
    conf_form = None
    skeys = None

    if request.method == 'POST':
        if 'disable' in request.POST:
            with get_bound_ldapuser(request) as user:
                dev.disable(user)
        elif 'confirm' in request.POST and 'otp_secret' in request.session:
            secret = request.session['otp_secret']
            conf_form = OTPForm(request.POST)
            try:
                if not conf_form.is_valid():
                    raise OkupyError()
                token = conf_form.cleaned_data['otp_token']

                # prevent reusing the same token to login
                if not RevokedToken.add(token, request.user):
                    raise OkupyError()
                if not dev.verify_token(token, secret):
                    raise OkupyError()
            except OkupyError:
                messages.error(request, 'Token verification failed.')
                conf_form = OTPForm()
            else:
                with get_bound_ldapuser(request) as user:
                    dev.enable(user, secret)
                    secret = None
                    conf_form = None
                    sdev = SOTPDevice.objects.get(user=request.user)
                    skeys = sdev.gen_keys(user)
                messages.info(request, 'The new secret has been set.')
        elif 'enable' in request.POST:
            secret = dev.gen_secret()
            request.session['otp_secret'] = secret
            conf_form = OTPForm()
        elif 'recovery' in request.POST:
            sdev = SOTPDevice.objects.get(user=request.user)
            with get_bound_ldapuser(request) as user:
                skeys = sdev.gen_keys(user)
            messages.info(request, 'Your old recovery keys have been revoked.')
        elif 'cancel' in request.POST:
            messages.info(request, 'Secret change aborted. Previous settings'
                          'are in effect.')

    if secret:
        # into groups of four characters
        secret = ' '.join([secret[i:i + 4]
                           for i in range(0, len(secret), 4)])
    if skeys:
        # xxx xx xxx
        def group_key(s):
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
