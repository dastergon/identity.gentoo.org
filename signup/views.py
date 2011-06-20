from django.conf import settings
from django.template import RequestContext
from django.shortcuts import render_to_response
from okupy.libraries.encryption import sha1Password
from okupy.libraries.ldap_wrappers import *
from okupy.libraries.exception import OkupyException
from okupy.signup.forms import SignupForm
import ldap.modlist as modlist
import logging

logger = logging.getLogger(__name__)

def checkPassword(request, credentials, form):
    '''
    Check if the passwords match
    '''
    if form.cleaned_data['password1'] == form.cleaned_data['password2']:
        credentials['username'] = str(form.cleaned_data['username'])
        credentials['password'] = sha1Password(form.cleaned_data['password1'])
        return
    else:
        msg = 'passwords don\'t match'
        logger.error(msg)
        raise OkupyException(msg)

def checkDuplicates(request, credentials):
    '''
    Check if the username or email already exist
    in the LDAP server
    '''
    try:
        results_name = ldap_user_search()
        results_mail = ldap_user_search('mail', credentials['email'])
    except ldap.NO_SUCH_OBJECT:
        '''
        The LDAP server is completely empty,
        '''
        return False
    if not results_name and not results_mail:
        return True
    else:
        msg = 'Error with the LDAP server'
        logger.error(msg)
        raise OkupyException(msg)

def addDataToLDAP(request, status, credentials):
    print credentials
    print credentials['first_name']
    '''
    Need to bind with the admin user to create new accounts
    '''
    ldap_admin_user_username = settings.LDAP_ADMIN_USER_DN.split('=')[1].split(',')[0]
    ldap_admin_user_attr = settings.LDAP_ADMIN_USER_DN.split('=')[0]
    ldap_admin_user_base_dn = ','.join(settings.LDAP_ADMIN_USER_DN.split(',')[1:])
    l = ldap_bind(ldap_admin_user_username,
            settings.LDAP_ADMIN_USER_PW,
            ldap_admin_user_attr,
            ldap_admin_user_base_dn)
    if status == 1:
        '''
        LDAP server is empty, before adding the new user,
        the top O and OUs need to be created first
        '''
        init_attrs_o = {
            'objectClass': settings.LDAP_O_NAME.values()[0],
            'dc': [settings.LDAP_O_NAME.keys()[0].split('=')[1].split(',')[0]],
            'o': [''.join(settings.LDAP_O_NAME.keys()[0].split('dc=')).replace(',', '.')],
        }
        ldif1 = modlist.addModlist(init_attrs_o)
        try:
            l.add_s(settings.LDAP_O_NAME.keys()[0], ldif1)
        except Exception as error:
            logger.error(error)
            raise OkupyException('Error with the LDAP server')
        for key, value in settings.LDAP_OU_LIST.iteritems():
            init_attrs_ou = {
                'objectClass': value,
                'ou': [key.split('=')[1].split(',')[0]],
            }
            ldif2 = modlist.addModlist(init_attrs_ou)
            try:
                l.add_s(key, ldif2)
            except Exception as error:
                logger.error(error)
                raise OkupyException('Error with the LDAP server')
    '''
    Collect the new user's credentials in a dictionary
    '''
    new_user_attrs = {}
    for field, attr in settings.LDAP_USER_ATTR_MAP.iteritems():
        new_user_attrs[attr] = [str(credentials[field])]
    new_user_attrs['objectClass'] = settings.LDAP_NEW_USER_OBJECTCLASS
    new_user_attrs['userPassword'] = [credentials['password']]
    '''
    Create some non-standard required attributes
    '''
    if 'person' in settings.LDAP_NEW_USER_OBJECTCLASS:
        new_user_attrs['cn'] = [str(credentials['first_name'] + ' ' + credentials['last_name'])]
    if 'posixAccount' in settings.LDAP_NEW_USER_OBJECTCLASS:
        try:
            new_user_attrs['uidNumber'] = [str(int(max(ldap_user_search()[-1][1]['uidNumber']) + 1))]
        except TypeError:
            new_user_attrs['uidNumber'] = ['1']
        new_user_attrs['gidNumber'] = ['100']
        new_user_attrs['homeDirectory'] = ['/home/%s' % credentials['username']]
    ldif = modlist.addModlist(new_user_attrs)
    try:
        l.add_s('uid=%s,%s' % (credentials['username'], settings.LDAP_NEW_USER_BASE_DN), ldif)
    except Exception as error:
        logger.error(error)
        raise OkupyException('Error with the LDAP server')
    l.unbind_s()

def signup(request):
    '''
    Credentials dictionary to initialize
    users' required attributes
    '''
    credentials = {
        'fist_name': '',
        'last_name': '',
        'email':'',
        'username':'',
        'password':'',
    }
    msg = ''
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            '''
            If any of the following functions fail, they
            will raise the exception at the end
            '''
            try:
                '''
                Check if passwords match
                '''
                checkPassword(request, credentials, form)
                '''
                Check if username or email are already there
                '''
                result = checkDuplicates(request, credentials)
                if result:
                    credentials['first_name'] = form.cleaned_data['first_name']
                    credentials['last_name'] = str(form.cleaned_data['last_name'])
                    credentials['email'] = str(form.cleaned_data['email'])
                    addDataToLDAP(request, 0, credentials)
                else:
                    '''
                    LDAP DB is empty, create the top O and OUs first
                    '''
                    addDataToLDAP(request, 1, credentials)
                return render_to_response('signup.html', credentials, context_instance = RequestContext(request))
            except OkupyException as error:
                msg = error.value
                logger.error(error)
    else:
         form = SignupForm()
    return render_to_response(
        'signup.html',
        {'msg': msg, 'form': form},
        context_instance = RequestContext(request))