# -*- coding: utf-8 -*-

# Django settings for okupy project.

from django.conf.global_settings import TEMPLATE_CONTEXT_PROCESSORS
import os

# Full path of the project dir
PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__)) + '/../..'

ADMINS = (
    ('admin', 'admin@example.com'),
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '',
    }
}

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'secret'

# LDAP settings

import ldap

AUTH_LDAP_SERVER_URI = 'ldap://ldap.example.com'

AUTH_LDAP_CONNECTION_OPTIONS = {
    ldap.OPT_REFERRALS: 0,
    ldap.OPT_X_TLS_DEMAND: False,
}

AUTH_LDAP_BIND_DN = ''
AUTH_LDAP_BIND_PASSWORD = ''

AUTH_LDAP_ADMIN_BIND_DN = ''
AUTH_LDAP_ADMIN_BIND_PASSWORD = ''

AUTH_LDAP_USER_ATTR = 'uid'
AUTH_LDAP_USER_BASE_DN = 'ou=people,o=test'
AUTH_LDAP_USER_DN_TEMPLATE = AUTH_LDAP_USER_ATTR + '=%(user)s,' + AUTH_LDAP_USER_BASE_DN

AUTH_LDAP_PERMIT_EMPTY_PASSWORD = False

AUTH_LDAP_START_TLS = False

#AUTH_LDAP_GROUP_SEARCH
#AUTH_LDAP_GROUP_TYPE
#AUTH_LDAP_REQUIRE_GROUP
#AUTH_LDAP_DENY_GROUP
#AUTH_LDAP_CACHE_GROUPS
#AUTH_LDAP_GROUP_CACHE_TIMEOUT
#AUTH_LDAP_FIND_GROUP_PERMS

#AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    #'is_active': '',
    #'is_staff': '',
    #'is_superuser': '',
#}

#AUTH_LDAP_PROFILE_FLAGS_BY_GROUP = {}

AUTH_LDAP_USER_OBJECTCLASS = ["person", "organizationalPerson", "inetOrgPerson", "posixAccount"]

# DEBUG Options: Select "True" for development use, "False" for production use
DEBUG = False
TEMPLATE_DEBUG = DEBUG

# Instance name, used in:
# * prefix of the notification mails: "[${INSTANCE_NAME}] ${TITLE}"
# * log dir name: /var/log/${INSTANCE_NAME}
# * console logs: ${INSTANCE_NAME} ${IP} ${ERROR}
INSTANCE_NAME = 'okupy-test'

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
ALLOWED_HOSTS = []

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'UTC'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = PROJECT_ROOT + '/media/'

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = '/media/'

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = PROJECT_ROOT + '/static/'

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or
    # "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    PROJECT_ROOT + '/okupy/static',
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'compressor.finders.CompressorFinder',
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
#    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # Uncomment the next line for simple clickjacking protection:
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    PROJECT_ROOT + '/okupy/templates/'
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
    'okupy.tests'
)

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
        'okupy': {
            'format': '%(instance_name)s: %(levelname)s %(id_name)s %(client_ip)s Message: %(message)s File: %(module)s Function: %(funcName)s Line: %(lineno)d',
        },
        'django_auth_ldap': {
            'format': 'django-auth-ldap: %(levelname)s Message: %(message)s',
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
            'formatter': 'okupy',
        },
        'syslog': {
            'level': 'INFO',
            'class': 'logging.handlers.SysLogHandler',
            'formatter': 'okupy',
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
            'handlers': ['console' if DEBUG else 'syslog'],
            'level': 'DEBUG' if DEBUG else 'INFO',
        },
    }
}

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_URL = '/logout/'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Custom authentication backend
AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
)

EMAIL_SUBJECT_PREFIX = '[%s]: ' % INSTANCE_NAME
SERVER_EMAIL = 'no-reply@example.com'

#Compressor Settings
COMPRESS_ENABLED = False
COMPRESS_PARSER = 'compressor.parser.HtmlParser'
