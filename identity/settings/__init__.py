# -*- coding: utf-8 -*-

# Django settings for identity.gentoo.org project.

from django.conf.global_settings import TEMPLATE_CONTEXT_PROCESSORS
import os

# Full path of the project dir
PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__)) + '/../..'

try:
    from local_settings import *
except ImportError:
    raise Exception('No local_settings.py found, please copy local_settings.py.sample and edit it accordingly')

if DEVELOPMENT:
    try:
        from development import *
    except ImportError:
        raise Exception('No development.py found, please copy development.py.sample and edit it accordingly if needed')
else:
    from production import *

MANAGERS = ADMINS

SITE_ID = 1

ROOT_URLCONF = 'identity.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'identity.wsgi.application'

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters':{
        'identity': {
            'format': '%(instance_name)s: %(levelname)s %(id_name)s %(client_ip)s Message: %(message)s File: %(module)s Function: %(funcName)s Line: %(lineno)d',
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
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'identity',
        },
        'syslog': {
            'level': 'INFO',
            'class': 'logging.handlers.SysLogHandler',
            'formatter': 'identity',
            'address': '/dev/log',
        },
    },
    'loggers': {
        'mail_identity': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
        'identity': {
            'handlers': ['console' if DEBUG else 'syslog'],
            'level': 'DEBUG' if DEBUG else 'INFO',
        },
    }
}

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_URL = '/logout/'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Custom user profile
AUTH_PROFILE_MODULE = 'accounts.UserProfile'

# Custom authentication backend
AUTHENTICATION_BACKENDS = (
    'identity.accounts.backends.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
)

# email sending variables regarding server authentication
# and configuration should be specified in local_settings
EMAIL_SUBJECT_PREFIX = '[%s] ' % INSTANCE_NAME
