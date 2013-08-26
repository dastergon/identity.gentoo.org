# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.utils.decorators import available_attrs
from django.utils.encoding import force_str

from functools import wraps
try:
    from urllib.parse import urlparse
except ImportError:  # Python 2
    from urlparse import urlparse


def strong_auth_required(function=None,
                         redirect_field_name=REDIRECT_FIELD_NAME,
                         login_url=None):
    """
    Decorator that enforces strong authentication (user bind)
    in function scope.

    It checks whether user has secondary password set. If he has one,
    it sets up LDAP database connection to use it. Otherwise, it
    redirects to login with stronger authentication request.
    """
    # most of the code ripped off django.contrib.auth
    def decorator(view_func):
        @wraps(view_func, assigned=available_attrs(view_func))
        def _wrapped_view(request, *args, **kwargs):
            if 'secondary_password' in request.session:
                return view_func(request, *args, **kwargs)
            request.session['strong_auth_requested'] = True

            # -- ripoff starts here --
            path = request.build_absolute_uri()
            # urlparse chokes on lazy objects in Python 3, force to str
            resolved_login_url = force_str(
                resolve_url(login_url or settings.LOGIN_URL))
            # If the login url is the same scheme and net location then just
            # use the path as the "next" url.
            login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
            current_scheme, current_netloc = urlparse(path)[:2]
            if ((not login_scheme or login_scheme == current_scheme) and
                    (not login_netloc or login_netloc == current_netloc)):
                path = request.get_full_path()
            return redirect_to_login(
                path, resolved_login_url, redirect_field_name)
        return _wrapped_view
    if function:
        return decorator(function)
    return decorator


def anonymous_required(view_function, redirect_to=None):
    """
    Decorator that implements the opposite functionality of login_required
    http://blog.motane.lu/2010/01/06/django-anonymous_required-decorator/
    """
    return AnonymousRequired(view_function, redirect_to)


class AnonymousRequired(object):
    def __init__(self, view_function, redirect_to):
        if redirect_to is None:
            redirect_to = settings.LOGIN_REDIRECT_URL
        self.view_function = view_function
        self.redirect_to = redirect_to

    def __call__(self, request, *args, **kwargs):
        if request.user is not None and request.user.is_authenticated():
            return HttpResponseRedirect(self.redirect_to)
        return self.view_function(request, *args, **kwargs)
