from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response
from django.template import RequestContext
from identity.accounts.backends import LDAPBackend
from identity.accounts.forms import *
from identity.accounts.models import *
from identity.common.encryption import *
from identity.common.exceptions import OkupyException
from identity.common.ldap_wrappers import *
from identity.common.log import log_extra_data
import ldap
import ldap.modlist as modlist
import logging

logger = logging.getLogger('identity')

def checkUsername(request, username):
    '''
    Check if the username given in the URL is correct
    This function checks if the user we requested to view
    is the same as the one who logged in, and if not,
    check if the requested user is validated (has a
    mail address under his account
    '''
    if username == request.user.username:
        return True
    else:
        other_user = ldap_user_search(username)
        try:
            if other_user[0][1]['mail']:
                return True
        except (KeyError, TypeError):
            pass
    return False

def checkPrivilegedUser(request, username):
    '''
    Check if the user is a member of the privileged
    groups that has permissions to edit other users' data
    '''
    for item in settings.LDAP_ACL_GROUPS_EDIT:
        if getattr(request.user.get_profile(), item):
            return True
    return False

@login_required
def account(request, username):
    msg = ''
    user = ''
    current_user_full = ''
    shown_attrs = ''
    try:
        if not checkUsername(request, username):
            raise OkupyException('Invalid URL')
        '''
        If the user is not in the DB already, he should be transfered from
        the LDAP
        '''
        current_user = LDAPBackend()
        current_user = current_user.get_or_create_user(username = username, other = True)
        '''
        Create a dictionary with all the user's data, and keep only the ones that
        should be public
        '''
        current_user_profile = eval(settings.AUTH_PROFILE_MODULE.split('accounts.')[1]).objects.get(user__username = username)
        current_user_full = dict(current_user.__dict__.items() + current_user_profile.__dict__.items())
        privil = checkPrivilegedUser(request, username)
        shown_attrs = settings.LDAP_PROFILE_PUBLIC_ATTRIBUTES
        if privil:
            shown_attrs = shown_attrs + settings.LDAP_PROFILE_PRIVATE_ATTRIBUTES + settings.LDAP_ACL_GROUPS.keys()
        else:
            if request.user.username == username:
                shown_attrs = shown_attrs + settings.LDAP_PROFILE_PRIVATE_ATTRIBUTES
        for key in current_user_full.keys():
            if key not in shown_attrs:
                del current_user_full[key]
    except OkupyException as error:
        msg = error.value
        logger.error(msg, extra = log_extra_data(request))
    return render_to_response(
        'account/account.html',
        {'current_user': current_user_full, 'msg': msg, 'attr_list': shown_attrs},
        context_instance = RequestContext(request))

@login_required
def account_edit(request, username):
    msg = ''
    form = ''
    try:
        privil = checkPrivilegedUser(request, username)
        if not request.user.username == username and not privil:
            raise OkupyException('Invalid URL')
        if not checkUsername(request, username):
            raise OkupyException('Invalid URL')
        '''
        If the user is not in the DB already, he should be transfered from
        the LDAP
        '''
        user = LDAPBackend()
        user = user.get_or_create_user(username = username, other = True)

        user_profile = eval(settings.AUTH_PROFILE_MODULE.split('accounts.')[1])
        user_profile_form = eval(settings.AUTH_PROFILE_MODULE.split('accounts.')[1] + 'Form')
        user_profile_privil_form = eval(settings.AUTH_PROFILE_MODULE.split('accounts.')[1] + 'PrivilForm')
        instance = user_profile.objects.get(user__username = username)
        if request.method == 'POST':
            if privil:
                form = user_profile_privil_form(request.POST, instance = instance)
            else:
                form = user_profile_form(request.POST, instance = instance)
            # Bind as the current user
            l = ldap_current_user_bind(
                request.user.username,
                decrypt_password(request.session['secondary_password']))
            # Update the data in LDAP first
            credentials = {}
            for item in settings.LDAP_PROFILE_PUBLIC_ATTRIBUTES + settings.LDAP_PROFILE_PRIVATE_ATTRIBUTES:
                try:
                    if eval('request.user.get_profile().' + str(item)) != request.POST.get(item) and request.POST.get(item):
                        credentials[item] = request.POST.get(item)
                        if eval('request.user.get_profile().' + str(item)):
                            print 'test'
                            mod_attrs = [(ldap.MOD_REPLACE, item, str(credentials[item]))]
                        else:
                            mod_attrs = [(ldap.MOD_ADD, item, str(credentials[item]))]
                        try:
                            l.modify_s('uid=%s,%s' % (username, settings.LDAP_NEW_USER_BASE_DN), mod_attrs)
                        except Exception as error:
                            logger.error(error, extra = log_extra_data(request))
                            raise OkupyException('Error with the LDAP server')
                        l.unbind_s()
                except AttributeError:
                    pass
                # Update the data in the DB
                try:
                    setattr(instance, item, credentials[item])
                except (AttributeError, KeyError):
                    pass
                try:
                    instance.save()
                except Exception as error:
                    logger.error(error, extra = log_extra_data(request))
                    raise OkupyException('Could not save to DB')
        else:
            if privil:
                form = user_profile_privil_form(instance = instance)
            else:
                form = user_profile_form(instance = instance)
    except OkupyException as error:
        msg = error.value
        logger.error(msg, extra = log_extra_data(request))
    return render_to_response(
        'account/edit.html',
        {'form': form, 'msg': msg},
        context_instance = RequestContext(request))

@login_required
def account_edit_password(request, username):
    msg = ''
    form = ''
    try:
        if not request.user.username == username:
            raise OkupyException('Invalid URL')
        if request.method == 'POST':
            form = PasswordForm(request.POST)
            if form.is_valid():
                if form.cleaned_data['password1'] != form.cleaned_data['password2']:
                    raise OkupyException('Passwords don\'t match')
                l = ldap_current_user_bind(username = username, password = form.cleaned_data['old_password'])
                if l:
                    base_dn = settings.LDAP_BASE_ATTR + '=' + request.user.username + request.user.get_profile().base_dn
                    l.passwd_s(base_dn, form.cleaned_data['old_password'], form.cleaned_data['password1'])
                else:
                    raise OkupyException('Old password is wrong Or there is a problem with the LDAP server')
                l.unbind_s()
                msg = 'Password changed successfully'
        else:
            form = PasswordForm()
    except OkupyException as error:
        msg = error.value
        logger.error(msg, extra = log_extra_data(request))
    return render_to_response(
        'account/password.html',
        {'form': form, 'msg': msg},
        context_instance = RequestContext(request))

@login_required
def account_all(request):
    l = ldap_anon_user_bind()
    accounts = {'uid': [], 'cn': []}
    user = ''
    for ldap_base_dn in settings.LDAP_BASE_DN:
        try:
            for user in l.search_s(ldap_base_dn,
                       ldap.SCOPE_SUBTREE,
                       '(%s=%s)' % (settings.LDAP_BASE_ATTR, '*'),
                       ['uid', 'cn'])
                accounts['uid'].append(user[1]['uid'][0])
                accounts['cn'].append(user[1]['cn'][0])
        except Exception as error:
            logger.error(error, extra = log_extra_data())
            raise OkupyException('Error with the LDAP server')
    l.unbind_s()
    return render_to_response('account/all.html', accounts, context_instance = RequestContext(request))
