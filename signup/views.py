from django.conf import settings
from djago.template import RequestContext
from django.shortcuts import render_to_response
from okupy.libraries.encryption import sha1Password
from okupy.libraries.ldap_q import *
from okupy.signup.forms import SignupForm
import ldap.modlist as modlist

'''
Global dictionary to initialize
users' required attributes
'''
credentials = {
    'fist_name': '',
    'last_name': '',
    'email':'',
    'username':'',
    'password':'',
}

def checkPassword(request):
    '''
    Check if the passwords match
    '''
    if request.POST.get('password1') == request.POST.get('password2'):
        return True
    else:
        # log 'passwords don't match'
        # raise Error('passwords don\'t match')
        return False

def checkDuplicates(request):
    '''
    Check if the username or email already exist
    in the LDAP server
    '''
    attributes = ['username', 'email']
    results = ldap_search(attributes)
    if not results:
        return True
    else:
        return False

def addDataToLDAP(request):
    global credentials
    attrs = {
        'objectclass': settings.LDAP_NEW_USER_OBJECTCLASS,
        'uid': [credentials['username']],
        'sn': [credentials['last_name']],
        'givenName': [credentials['last_name']],
        'email': [credentials['email']],
    }
    l = ldap_bind(settings.LDAP_ADMIN_USER_DN, settings.LDAP_ADMIN_USER_PW)
    try:
        if l:
            ldif = modlist.addModlist(attrs)
            try:
                l.add_s('uid=%s,%s' % (credentials['username'], settings.LDAP_BASE_DN[0]), ldif)
            except:
                init_attrs_o = {
                    'objectClass': settings.LDAP_O_NAME.values()[0],
                    'dn': settings.LDAP_O_NAME.keys(),
                    'dc': [settings.LDAP_O_NAME.keys()[0].split('=')[1].split(',')[0]],
                    'o': [''.join(settings.LDAP_O_NAME.keys()[0].split('dc=')).replace(',', '.')],
                }
                ldif1 = modlist.addModlist(init_attrs_o)
                try:
                    l.add_s(init_attrs_o['o'][0], ldif1)
                except:
                    pass
                
                for key, value in settings.LDAP_OU_LIST.iteritems():
                    init_attrs_ou = {
                        'dn': [key],
                        'objectClass': [value],
                        'ou': [key.split('=')[1].split(',')[0]],
                    }
                    ldif2 = modlist.addModlist(init_attrs_ou)
                    try:
                        l.add_s(init_attrs_ou['ou'][0], ldif2)
                    except:
                        pass
            l.unbind_s()
    except AttributeError:
        # log invalid root credentials
        pass

def signup(request):
    global credentials
    msg = ''
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            if checkPassword(request):
                credentials['username'] = request.POST.get('username')
                credentials['password'] = sha1Password(request.POST.get('password1'))
            else:
                msg = 'passwords don\'t match'
            if checkDuplicates(request):
                credentials['first_name'] = request.POST.get('first_name')
                credentials['last_name'] = request.POST.get('last_name')
                credentials['email'] = request.POST.get('email')
            else:
                msg = 'User already exists'
            addDataToLDAP
    else:
         form = SignupForm()
    return render_to_response(
        'signup.html',
        {'msg': msg, 'form': form},
        context_instance = RequestContext(request)
    )