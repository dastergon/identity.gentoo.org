# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

# Django settings for okupy project.

from django.conf.global_settings import TEMPLATE_CONTEXT_PROCESSORS
import os

# Full path of the project dir
PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__)) + '/../..'

SITE_ID = 1

ROOT_URLCONF = 'okupy.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'okupy.wsgi.application'

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_URL = '/logout/'

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_COOKIE_AGE = 900

MESSAGE_STORAGE = 'django.contrib.messages.storage.session.SessionStorage'

# Custom authentication backend
AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'okupy.common.auth.SSLCertAuthBackend',
)

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
    'django_auth_ldap',
    'django_otp',
    'discover_runner',
    'okupy.accounts',
    'okupy.otp',
    'okupy.otp.sotp',
    'okupy.otp.totp',
    'okupy.tests',
)

#Compressor settings
COMPRESS_ENABLED = False
COMPRESS_PARSER = 'compressor.parser.HtmlParser'

ADMINS = (
    ('admin', 'admin@example.com'),
)

# Instance name, used in:
# * log dir name: /var/log/okupy/${INSTANCE_NAME}
# * console logs: ${INSTANCE_NAME} ${IP} ${ERROR}
# * prefix of the notification mails: "[${INSTANCE_NAME}] ${TITLE}"
# * (production only): {MEDIA,STATIC}_ROOT:
# /var/www/${INSTANCE_NAME}/htdocs/{media,static}
# Examples: okupy, okupy-dev, identity.gentoo.org
INSTANCE_NAME = 'okupy-test'

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

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
    ldap.OPT_REFERRALS: 1,
    ldap.OPT_X_TLS_DEMAND: True,
}

AUTH_LDAP_BIND_DN = 'cn=anon,o=test'
AUTH_LDAP_BIND_PASSWORD = 'anonpassword'

AUTH_LDAP_ADMIN_BIND_DN = 'cn=Manager,o=test'
AUTH_LDAP_ADMIN_BIND_PASSWORD = 'adminpassword'

AUTH_LDAP_USER_ATTR = 'uid'
AUTH_LDAP_USER_BASE_DN = 'ou=people,o=test'

AUTH_LDAP_PERMIT_EMPTY_PASSWORD = False

AUTH_LDAP_START_TLS = True

# objectClasses that are used by any user
AUTH_LDAP_USER_OBJECTCLASS = ['top', 'person', 'organizationalPerson',
                              'inetOrgPerson', 'posixAccount', 'shadowAccount']
# additional objectClasses that are used by developers
AUTH_LDAP_DEV_OBJECTCLASS = ['developerAccount']

# DEBUG Options: Select "True" for development use, "False" for production use
DEBUG = False
TEMPLATE_DEBUG = DEBUG

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

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    PROJECT_ROOT + '/okupy/templates/'
)

MANAGERS = ADMINS

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

AUTH_LDAP_USER_DN_TEMPLATE = AUTH_LDAP_USER_ATTR + '=%(user)s,' + AUTH_LDAP_USER_BASE_DN

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

TEST_RUNNER = 'discover_runner.DiscoverRunner'

DIRECTORY = {
    "o=test": {},
    "cn=anon,o=test": {
        "userPassword": ["{CRYPT}$1$n4jlXi20$.5a8UTvwIqVfVAMlXJ1EZ0"],
    },
    "cn=Manager,o=test": {
        "userPassword": ["{CRYPT}$1$sY4mlRve$0eg5TLYMyZfBCIUgU/RPf0"],
    },
    "ou=people,o=test": {},
    "uid=alice,ou=people,o=test": {
        "uid": ["alice"],
        "userPassword": ['{CRYPT}$1$lO/RU6zz$2fJCOwurxBtCqdImkoLQo1'],
        "objectClass": AUTH_LDAP_USER_OBJECTCLASS + AUTH_LDAP_DEV_OBJECTCLASS,
        "uidNumber": ["1000"],
        "gidNumber": ["1000"],
        "givenName": ["Alice"],
        "sn": ["Adams"],
        "mail": ["alice@test.com"],
    },
    "uid=bob,ou=people,o=test": {
        "uid": ["bob"],
        "userPassword": ['{CRYPT}$1$eFSQMJY6$8y.WUL/ONeEarVXqeCIbH.'],
        "objectClass": AUTH_LDAP_USER_OBJECTCLASS,
        "uidNumber": ["1001"],
        "gidNumber": ["50"],
        "givenName": ["Robert"],
        "sn": ["Barker"],
        "mail": ["bob@test.com"],
    }
}
