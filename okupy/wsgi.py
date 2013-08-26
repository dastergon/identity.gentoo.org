# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python
"""
WSGI config for okupy project.

This module contains the WSGI application used by Django's development server
and any production WSGI deployments. It should expose a module-level variable
named ``application``. Django's ``runserver`` and ``runfcgi`` commands discover
this application via the ``WSGI_APPLICATION`` setting.

Usually you will have the standard Django WSGI application here, but it also
might make sense to replace the whole Django WSGI application with a custom one
that later delegates to the Django one. For example, you could introduce WSGI
middleware here, or combine a Django application with an application of another
framework.

"""
import os

# We defer to a DJANGO_SETTINGS_MODULE already in the environment. This breaks
# if running multiple sites in the same mod_wsgi process. To fix this, use
# mod_wsgi daemon mode with each site in its own daemon process, or use
# os.environ["DJANGO_SETTINGS_MODULE"] = "okupy.settings"
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okupy.settings")

# This application object is used by any WSGI server configured to use this
# file. This includes Django's development server, if the WSGI_APPLICATION
# setting points here.
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()

# Apply WSGI middleware here.
# from helloworld.wsgi import HelloWorldApplication
# application = HelloWorldApplication(application)

# from http://projects.unbit.it/uwsgi/wiki/TipsAndTricks
# AUTHOR: Simone Federici
try:
    # uwsgi module is only available when running from uwsgi
    import uwsgi
except ImportError:
    # we're probably running from django's built-in server
    pass
else:
    from uwsgidecorators import postfork, thread, timer
    from django.utils import autoreload

    # autodiscover SSH handlers
    import okupy.accounts.ssh  # noqa
    from okupy.common.ssh import ssh_main

    import Crypto.Random

    postfork(thread(ssh_main))

    @postfork
    def reset_rng():
        Crypto.Random.atfork()

    @timer(5)
    def change_code_gracefull_reload(sig):
        if autoreload.code_changed():
            uwsgi.reload()
