#!/usr/bin/env python
# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from setuptools import setup, find_packages
import glob
import okupy
import os

extra_deps = {}
files = glob.glob('requirements/extras/*')
for path in files:
    extra_deps[os.path.basename(path).split('.')[0]] = open(path).read().split('\n')[0]

with open('requirements/base.txt', 'r') as f:
    base_deps = []
    for line in f:
        if line.startswith('git+') or line.startswith('hg+'):
            base_deps.append(line.split('#egg=')[1])
        else:
            base_deps.append(line.split('\n')[0])

with open('requirements/tests.txt', 'r') as f:
    test_deps = []
    for line in f:
        if line.startswith('git+') or line.startswith('hg+'):
            test_deps.append(line.split('#egg=')[1])
        else:
            test_deps.append(line.split('\n')[0])
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
    install_requires=base_deps,
    setup_requires=[
        'setuptools>=0.6c11',
    ],
    tests_require=test_deps,
    extras_require=extra_deps,
)
