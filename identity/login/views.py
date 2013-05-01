from django import http
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext, loader
from identity.common.encryption import *
from identity.common.exceptions import OkupyException
from identity.common.ldap_cleanup import ldap_second_passwd_cleanup
from identity.common.ldap_wrappers import *
from identity.common.log import log_extra_data
from identity.login.forms import LoginForm
import logging

logger = logging.getLogger('identity')

def mylogin(request):
    msg = ''
    form = ''
    if request.method == 'POST':
        if request.POST.get('signup'):
            return HttpResponseRedirect('/signup')
        form = LoginForm(request.POST)
        if form.is_valid():
            mail = form.cleaned_data['mail']
            password = form.cleaned_data['password']
            try:
                '''
                Try to authenticate using the LDAP backend
                '''
                user = authenticate(mail = mail, password = password)
                if user is not None:
                    '''
                    If the LDAP backend returns a user object, then the
                    log in is successfull
                    '''
                    if user.is_active:
                        login(request, user)
                        '''
                        Create the secondary password for the user
                        '''
                        l = ldap_current_user_bind(user.username, password)
                        result = ldap_user_search(filter = user.username, l = l, unbind = False)
                        if len(result[0][1]['userPassword']) > 1:
                            for hash in result[0][1]['userPassword']:
                                '''
                                There is a leftover secondary password, removing
                                '''
                                if not check_password(hash, password):
                                    ldap_second_passwd_cleanup(request, hash, l)
                        '''
                        Store the new secondary password in the session and in the LDAP
                        '''
                        secondary_password = random_string(48)
                        request.session['secondary_password'] = encrypt_password(secondary_password)
                        mod_attrs = [(ldap.MOD_ADD, 'userPassword', sha_password(secondary_password))]
                        try:
                            l.modify_s(result[0][0], mod_attrs)
                        except Exception as error:
                            logger.error(error, extra = log_extra_data(request, form))
                            l.unbind_s()
                            raise OkupyException('Could not modify LDAP data')
                        l.unbind_s()
                        if not form.cleaned_data['remember']:
                            request.session.set_expiry(0)
                        return HttpResponseRedirect('/')
                else:
                    msg = 'Wrong Credentials'
            except OkupyException as error:
                msg = error.value
                logger.error(msg, extra = log_extra_data(request, form))
    else:
        if request.user.is_authenticated():
            return HttpResponseRedirect('/')
        else:
            form = LoginForm()
    return render_to_response('login.html', {
            'msg': msg,
            'form': form,
        }, context_instance = RequestContext(request))

@login_required
def mylogout(request):
    l = ldap_current_user_bind(
        request.user.username,
        decrypt_password(request.session['secondary_password']))
    result = ldap_user_search(filter = request.user.username, l = l, unbind = False)
    for hash in result[0][1]['userPassword']:
        if check_password(hash, decrypt_password(request.session['secondary_password'])):
            ldap_second_passwd_cleanup(request, hash, l)
    l.unbind_s()
    logout(request)
    return HttpResponseRedirect('/')

def server_error(request, template_name='500.html'):
    """
    override 500 error page, in order to pass MEDIA_URL to Context
    """
    t = loader.get_template(template_name) # You need to create a 500.html template.
    return http.HttpResponseServerError(t.render(RequestContext(request, {'request_path': request.path})))
