from django.conf import settings
from okupy.libraries.exception import OkupyException, log_extra_data
import ldap
import logging

logger = logging.getLogger('okupy')

def ldap_bind(username = None, password = None, base_attr = None, base_dn = None):
    '''
    This function is responsible for the connection
    to the LDAP server.
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
    if username:
        '''
        The user's DN is constructed by the base_attr, which is
        usually cn or uid based on the OpenLDAP configuration,
        the username and the base_dn, eg dc=example,dc=com
        '''
        bind_dn = '%s=%s,%s' % (base_attr, username, base_dn)
        '''
        If the bind succeeds, this returns a python-ldap object,
        else it returns None.
        '''
        try:
            l.simple_bind_s(bind_dn, password)
            return l
        except Exception as error:
            logger.error(error, extra = log_extra_data())
            raise OkupyException('Could not bind to LDAP')
    else:
        '''
        If no attributes are given, then a simple anonymous bind
        is performed
        '''
        try:
            l.simple_bind_s()
            return l
        except Exception as error:
            logger.error(error, extra = log_extra_data())
            raise OkupyException('Could not bind to LDAP')

def ldap_anon_user_bind():
    '''
    If the anonymous search is disabled, it has to be
    done using the LDAP_ANON_USER account
    '''
    try:
        if settings.LDAP_ANON_USER_DN:
            ldap_anon_user_username = settings.LDAP_ANON_USER_DN.split('=')[1].split(',')[0]
            ldap_anon_user_attr = settings.LDAP_ANON_USER_DN.split('=')[0]
            ldap_anon_user_base_dn = ','.join(settings.LDAP_ANON_USER_DN.split(',')[1:])
            l = ldap_bind(ldap_anon_user_username,
                            settings.LDAP_ANON_USER_PW,
                            ldap_anon_user_attr,
                            ldap_anon_user_base_dn)
    except AttributeError:
        l = ldap_bind()
    return l

def ldap_user_search(filter = '*', attr = settings.LDAP_BASE_ATTR, results = None, anon = True, l = False):
    if anon:
        l = ldap_anon_user_bind()
    '''
    Perform LDAP query, it supports multiple OU's and attrs.
    Since there is ability to search in multiple OU's
    (eg ou=developers and ou=users). If there is a result
    available, the for loop should break
    '''
    user = ''
    for ldap_base_dn in settings.LDAP_BASE_DN:
        try:
            user = l.search_s(ldap_base_dn,
                        ldap.SCOPE_SUBTREE,
                        '(%s=%s)' % (attr, filter),
                        results)
        except Exception as error:
            logger.error(error, extra = log_extra_data())
            raise OkupyException('Error with the LDAP server')
        if user:
            break
    l.unbind_s()
    if not user:
        return None
    else:
        return user
