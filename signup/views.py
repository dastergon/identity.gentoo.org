from django.conf import settings
from djago.template import RequestContext
from django.shortcuts import render_to_response
from okupy.libraries.encryption import sha1Password
from okupy.signup.forms import SignupForm

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
    l = ldap.initialize(settings.LDAP_SERVER_URI)
    '''
    The following is run in case a TLS connection
    is requested
    '''
    try:
        if settings.LDAP_TLS:
            l.set_option(ldap.OPT_X_TLS_DEMAND, True)
            l.start_tls_s()
    except:
        pass
    '''
    Perform LDAP query to check for duplicates
    '''
    try:
        if settings.LDAP_ANON_USER_DN:
            l.simple_bind_s(
                settings.LDAP_ANON_USER_DN,
                settings.LDAP_ANON_USER_PW,
            )
    except ImportError, AttributeError:
        pass
    except ldap.INVALID_CREDENTIALS:
        # log 'anon account is invalid'
        return False

    for ldap_base_dn in settings.LDAP_BASE_DN:
        for attribute in username, email:
            results = l.search_s(ldap_base_dn,
                                ldap.SCOPE_SUBTREE,
                                '(%s=%s)' % (settings.LDAP_BASE_ATTR, attribute),
                                ['*'])
        '''
        Since there is ability to search in multiple OU's
        (eg ou=developers and ou=users), if there is a result
        available, the for loop should break
        '''
        try:
            if results:
                break
        except AttributeError:
            pass
    l.unbind_s()
    if not results:
        return True
    else:
        return False

#def addDataToLDAP(request):
#    todo

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
            # addDataToLDAP
    else:
         form = SignupForm()
    return render_to_response(
        'signup.html',
        {'msg': msg, 'form': form},
        context_instance = RequestContext(request)
    )