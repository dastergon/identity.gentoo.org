#!/usr/bin/env python
# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from setuptools import setup, find_packages
import okupy

setup(
    name='okupy',
    version=okupy.__version__,
    license='AGPLv3',
    author='identity.gentoo.org development team',
    author_email='identity@gentoo.org',
    url='http://github.com/gentoo/identity.gentoo.org',
    description='Django LDAP webUI and OpenID provider for the Gentoo Linux project',
    long_description=open('README.md').read(),
    keywords='django, ldap, gentoo',
    packages=find_packages(),
    include_package_data=True,
    test_suite='okupy.tests.runtests',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Students',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Framework :: Django',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development',
    ],
    dependency_links=[
        'https://bitbucket.org/psagers/mockldap/get/default.tar.gz#egg=mockldap',
        'https://github.com/tampakrap/django-ldapdb/archive/okupy.tar.gz#egg=django-ldapdb',
    ],
    install_requires=[
        'django>=1.5',
        'django-auth-ldap>=1.1.4',
        'django-compressor>=1.3',
        'django-ldapdb',
        'django-otp>=0.1.7',
        'paramiko>=1.10.1',
        'passlib>=1.6.1',
        'pycrypto>=2.6',
        'pyopenssl>=0.13',
        'python-ldap>=2.4.10',
        'python-memcached>=1.53',
        'python-openid>=2.2.5',
        'pytz>=2012j',
        'qrcode>=3.0',
    ],
    setup_requires=[
        'setuptools>=0.6c11',
    ],
    tests_require=[
        'django-discover-runner>=1.0',
        'mockldap',
        'mock>=1.0.1',
    ],
    extras_require={
        'mysql': ['mysql-python>=1.2.3'],
    },
)
