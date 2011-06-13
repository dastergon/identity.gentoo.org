from django.conf import settings
from django.contrib.auth.models import User
from okupy.accounts.models import *
import ldap

class LDAPBackend(object):
    '''
    LDAP authentication backend
    '''
    def bind(self, username, password, base_attr, base_dn):
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

    def authenticate(self, username = None, password = None):
        '''
        Try to authenticate the user. If there isn't such user
        in the Django DB, and assuming the credentials are correct,
        the user's data will be migrated from the LDAP server
        to the Django DB.
        '''
        if not password:
            return None
        return self.get_or_create_user(username, password)


    def get_user(self, user_id):
        '''
        Retrieve a specific user from the Django DB
        '''
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def get_or_create_user(self, username, password):
        '''
        Retrieves a user from the Django DB. If the user is not
        found in the DB, then it tries to retrieve it from the
        LDAP server. It needs the ability to perform an anonymous
        query, or a minimal privileged user (LDAP_ANON_USER_{DN,PW})
        should do it instead. If the user is found, the data are
        then moved to the Django DB.
        '''
        try:
            user = User.objects.get(username = username)
        except User.DoesNotExist:
            '''
            Perform a search to find the user in the LDAP server.
            It supports multiple OU's. The ldap search has to be
            done with a minimal privileged account if the anonymous
            searches are disabled.
            '''
            try:
                if settings.LDAP_ANON_USER_DN:
                    ldap_anon_user_username = settings.LDAP_ANON_USER_DN.split('=')[1].split(',')[0]
                    ldap_anon_user_attr = settings.LDAP_ANON_USER_DN.split('=')[0]
                    ldap_anon_user_base_dn = ','.join(settings.LDAP_ANON_USER_DN.split(',')[1:])
                    l = self.bind(ldap_anon_user_username,
                                    settings.LDAP_ANON_USER_PW,
                                    ldap_anon_user_attr,
                                    ldap_anon_user_base_dn)
            except ImportError, AttributeError:
                pass

            for ldap_base_dn in settings.LDAP_BASE_DN:
                results = l.search_s(ldap_base_dn,
                                    ldap.SCOPE_SUBTREE,
                                    '(%s=%s)' % (settings.LDAP_BASE_ATTR, username),
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
            if not results:
                return None
            l.unbind_s()

            '''
            In case there is a result available, it means
            that the user is in the LDAP server. Next step
            is to try to bind to the LDAP server using the
            user's credentials, to check if they are valid.
            '''
            for ldap_base_dn in settings.LDAP_BASE_DN:
                l_user = self.bind(username, password,
                                settings.LDAP_BASE_ATTR,
                                ldap_base_dn)
                '''
                Again, we need to search in multiple OU's for
                the user's existence.
                '''
                try:
                    if l_user:
                        break
                except AttributeError:
                    pass
            if not l_user:
                return None
            l_user.unbind()

            '''
            In case everything went fine so far, it means there is
            a valid user available. Last step is to migrate the user's
            data to the Django DB.
            '''
            user = User()
            for field, attr in settings.LDAP_USER_ATTR_MAP.iteritems():
                setattr(user, field, results[0][1][attr][0])
            user.set_unusable_password()
            try:
                user.save()
            except Exception as error:
                # log error
                pass

            '''
            Additional data that should be put in the user's profile
            '''
            try:
                if settings.LDAP_PROFILE_ATTR_MAP:
                    user_profile = settings.AUTH_PROFILE_MODULE
                    for field, attr in settings.LDAP_PROFILE_ATTR_MAP.iteritems():
                        setattr(user_profile, field, '::'.join(results[0][1][attr]))
                    '''
                    Check if the user is member of the groups under
                    settings.LDAP_ACL_GROUPS. In order to do this, the
                    system compares the contents of that list with the
                    values of the LDAP attribute settings.LDAP_ACL_ATTR.
                    For correct results, it sets the according is_field
                    of the UserProfile to True.
                    '''
                    for attr, field in settings.LDAP_ACL_GROUPS.iteritems():
                        if attr in results[0][1][settings.LDAP_ACL_ATTR]:
                            setattr(user_profile, field, True)

                    try:
                        user_profile.save()
                    except Exception as error:
                        # log error
                        pass
            except:
                pass

            return user