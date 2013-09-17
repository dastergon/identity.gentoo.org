# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.db.models import fields

from ldapdb import escape_ldap_filter

class ACLField(fields.Field):
    def _group(self):
        return self.name.split('_')[1] + '.group'

    def from_ldap(self, value, connection):
        if self._group() in value:
            return True
        else:
            return False

    def get_db_prep_lookup(self, lookup_type, value, connection, prepared=False):
        "Returns field's value prepared for database lookup."
        return [self.get_prep_lookup(lookup_type, value)]

    def get_db_prep_save(self, value, connection):
        return [x.encode(connection.charset) for x in value]

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if value not in (False, True):
            raise TypeError("Invalid value")
        if lookup_type == 'exact':
            if value:
                return escape_ldap_filter(self._group())
            else:
                raise NotImplementedError(
                    "Negative lookups on ACLField are not yet implemented")
        raise TypeError("ACLField has invalid lookup: %s" % lookup_type)
