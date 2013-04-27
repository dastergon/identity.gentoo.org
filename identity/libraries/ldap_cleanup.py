#from proj_root import *
import os
import sys
import ldap
from okupy.libraries.encryption import sha_password
from okupy.libraries.ldap_wrappers import *
from django.conf import settings
#sys.path.append(PROJECT_ROOT)
#os.environ['DJANGO_SETTINGS_MODULE'] = 'okupy.settings'

def ldap_second_passwd_cleanup(request, hash, l):
    base_dn = settings.LDAP_BASE_ATTR + '=' + request.user.username + request.user.get_profile().base_dn
    mod_attrs = [(ldap.MOD_DELETE, 'userPassword', hash)]
    try:
        l.modify_s(base_dn, mod_attrs)
    except Exception as error:
        logger.error(error, extra = log_extra_data(request))
