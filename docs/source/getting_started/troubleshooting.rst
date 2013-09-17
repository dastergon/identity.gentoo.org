Troubleshooting
===============
In a python terminal::

    import ldap
    l = ldap.initialize('ldap://identity.example.gr')
    l.start_tls_s()
    l.simple_bind_s()
    l.search_s('ou=users,dc=example,dc=gr', ldap.SCOPE_SUBTREE)

In a ``./manage.py`` shell terminal::

    from okupy.accounts.models import LDAPUser
    users = LDAPUser.objects.all()
    wolverine = LDAPUser.objects.get(username='wolverine')

