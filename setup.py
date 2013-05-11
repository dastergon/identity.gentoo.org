from setuptools import setup, find_packages
import okupy
import os
import sys

setup(
    name='okupy',
    version=okupy.__version__,
    license='AGPLv3',
    author='identity.gentoo.org development team',
    author_email='identity@gentoo.org',
    url='http://identity.gentoo.org',
    description='Django web frontend for Gentoo LDAP server',
    long_description=open(os.path.join(os.path.dirname(__file__), 'README.md')).read(),
    keywords='django, ldap, gentoo',
    packages=find_packages(),
    data_files=[('', ['LICENSE', 'manage.py'])],
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
    install_requires=[
        'django>=1.5',
        'django-auth-ldap>=1.1.4',
        'mysql-python>=1.2.3',
        'pycrypto>=2.6',
        'python-ldap>=2.4.10',
        'setuptools>=0.6.21',
    ],
    include_package_data=True,
)
