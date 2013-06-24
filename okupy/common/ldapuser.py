# -*- coding: utf-8 -*-

from django.conf import settings
from django_auth_ldap.config import _LDAPConfig
from okupy.common.exceptions import OkupyError
from okupy.common.log import log_extra_data
import logging

logger = logging.getLogger('okupy')
logger_mail = logging.getLogger('mail_okupy')

class OkupyLDAPConnection(object):
    @property
    def ldap(self):
        return _LDAPConfig.get_ldap(None)

    def _get_connection(self):
        self._connection = self.ldap.initialize(settings.AUTH_LDAP_SERVER_URI)

        for opt, value in settings.AUTH_LDAP_CONNECTION_OPTIONS.iteritems():
            self._connection.set_option(opt, value)

        if settings.AUTH_LDAP_START_TLS:
            self._connection.start_tls_s()
        return self._connection

class OkupyLDAPUser(OkupyLDAPConnection):
    def __init__(self, bind_dn = None, bind_password = None):
        try:
            if bind_dn:
                self._get_connection().simple_bind_s(
                    bind_dn.encode('utf-8'),
                    bind_password.encode('utf-8')
                )
            else:
                self._get_connection().simple_bind_s()
        except Exception as error:
            logger.critical(error, extra=log_extra_data())
            logger_mail.exception(error)
            raise OkupyError("Can't contact LDAP server")

    def search_s(self, dn = settings.AUTH_LDAP_USER_BASE_DN, scope = 'subtree', attr = settings.AUTH_LDAP_USER_ATTR, filterstr = '*', attrlist = '', attrsonly=0):
        if scope == 'base':
            scope = self.ldap.SCOPE_BASE
        elif scope == 'onelevel':
            scope = self.ldap.SCOPE_ONELEVEL
        elif scope == 'subtree':
            scope = self.ldap.SCOPE_SUBTREE

        try:
            self.search_results = self._get_connection().search_s(
                dn, scope, '(%s=%s)' % (attr, filterstr), attrlist, attrsonly
            )
            return self.search_results
        except Exception as error:
            logger.critical(error, extra=log_extra_data())
            logger_mail.exception(error)
            raise OkupyError("Can't contact LDAP server")

    def unbind_s(self):
        self.ldap.unbind()

    def add_s(self, dn, modlist):
        self.ldap.add_s(dn, modlist)
