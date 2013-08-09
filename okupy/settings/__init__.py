# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

# Django settings for okupy project.

from django.conf.global_settings import TEMPLATE_CONTEXT_PROCESSORS
import os

# Full path of the project dir
PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__)) + '/../..'

try:
    from .local import *
except ImportError:
    raise Exception('No settings/local.py found, please copy settings/local.py.sample and edit it accordingly')

if DEVELOPMENT:
    try:
        from .development import *
    except ImportError:
        raise Exception('No settings/development.py found, please copy settings/development.py.sample and edit it accordingly if needed')
else:
    from .production import *

MANAGERS = ADMINS

SITE_ID = 1

ROOT_URLCONF = 'okupy.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'okupy.wsgi.application'

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(instance_name)s: %(levelname)s %(id_name)s %(client_ip)s Message: %(message)s File: %(module)s Function: %(funcName)s Line: %(lineno)d',
        },
        'simple': {
            'format': '%(levelname)s Message: %(message)s File: %(module)s Function: %(funcName)s Line: %(lineno)d',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler',
            'include_html': True,
        },
        'console_v': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'syslog_v': {
            'level': 'INFO',
            'class': 'logging.handlers.SysLogHandler',
            'formatter': 'verbose',
            'address': '/dev/log',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'syslog': {
            'level': 'INFO',
            'class': 'logging.handlers.SysLogHandler',
            'formatter': 'simple',
            'address': '/dev/log',
        },
    },
    'loggers': {
        'mail_okupy': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
        'okupy': {
            'handlers': ['console_v' if DEBUG else 'syslog_v'],
            'level': 'DEBUG' if DEBUG else 'INFO',
        },
        'okupy_simple': {
            'handlers': ['console' if DEBUG else 'syslog'],
            'level': 'DEBUG' if DEBUG else 'INFO',
        },
        'django_auth_ldap': {
            'handlers': ['console' if DEBUG else 'syslog'],
            'level': 'DEBUG' if DEBUG else 'INFO',
        },
    }
}

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_URL = '/logout/'
SESSION_COOKIE_AGE = 900

AUTH_LDAP_USER_DN_TEMPLATE = AUTH_LDAP_USER_ATTR + '=%(user)s,' + AUTH_LDAP_USER_BASE_DN

# Custom authentication backend
AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
    'okupy.common.auth.ExternalBackend',
)

# email sending variables regarding server authentication
# and configuration should be specified in settings/local.py
EMAIL_SUBJECT_PREFIX = '[%s]: ' % INSTANCE_NAME

TEMPLATE_CONTEXT_PROCESSORS += (
    'django.core.context_processors.request',
)

# django-ldapdb settings
DATABASES['ldap'] = {
    'ENGINE': 'ldapdb.backends.ldap',
    'NAME': AUTH_LDAP_SERVER_URI,
    'USER': AUTH_LDAP_BIND_DN,
    'PASSWORD': AUTH_LDAP_BIND_PASSWORD,
    'CONNECTION_OPTIONS': AUTH_LDAP_CONNECTION_OPTIONS,
    'TLS': AUTH_LDAP_START_TLS,
}

DATABASE_ROUTERS = ['ldapdb.router.Router']

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # Uncomment the next line for simple clickjacking protection:
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

INSTALLED_APPS = (
    'compressor',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'okupy.accounts',
    'okupy.otp',
    'okupy.otp.sotp',
    'okupy.otp.totp',
)

#Compressor settings
COMPRESS_ENABLED = True
COMPRESS_PARSER = 'compressor.parser.HtmlParser'
