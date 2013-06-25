#!/usr/bin/env python
# vim:fileencoding=utf8:et:ts=4:sts=4:tw=4:ft=python

from setuptools import setup, find_packages
import okupy
import os

setup(
    name='okupy',
    version=okupy.__version__,
    license='AGPLv3',
    author='identity.gentoo.org development team',
    author_email='identity@gentoo.org',
    url='http://github.com/gentoo/identity.gentoo.org',
    description='Django LDAP webUI and OpenID provider for the Gentoo Linux project',
    long_description=open(os.path.join(os.path.dirname(__file__), 'README.md')).read(),
    keywords='django, ldap, gentoo',
    packages=find_packages(),
    data_files=[('', ['LICENSE', 'manage.py', 'README.md'])],
    include_package_data=True,
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
        # use tampakrap's fork, contains additional patches needed for the tests
        'https://bitbucket.org/tampakrap/django-auth-ldap/get/1.1.4.0.1.tar.gz#egg=django-auth-ldap-1.1.4.0.1',
    ],
    install_requires=[
        'django>=1.5',
        'django-auth-ldap>=1.1.4',
        'django-compressor>=1.3',
        'edpwd>=0.0.1',
        'passlib>=1.6.1',
        'python-ldap>=2.4.10',
    ],
    setup_requires=[
        'setuptools>=0.6c11',
    ],
    tests_require=[
        'mock>=1.0.1',
    ],
    extras_require={
        'mysql': ['mysql-python>=1.2.3'],
    },
)
