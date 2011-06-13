from django.conf import settings
import ldap

def ldap_bind(username, password, base_attr, base_dn):
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
    except ldap.INVALID_CREDENTIALS:
        # log 'invalid credentials'
        return None

def ldap_search(attributes):
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
        pass
    '''
    Perform LDAP query, it supports multiple OU's
    '''
    for ldap_base_dn in settings.LDAP_BASE_DN:
        for attr in attributes:
            results = l.search_s(ldap_base_dn,
                                ldap.SCOPE_SUBTREE,
                                '(%s=%s)' % (settings.LDAP_BASE_ATTR, attr),
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
        return None
    else:
        return results