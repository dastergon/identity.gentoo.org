# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.backends.cache import SessionStore
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.messages.storage.cookie import CookieStorage
from django.db import DatabaseError
from django.test import TestCase, RequestFactory
from django.utils.functional import curry

import mock


"""
Decorator that restricts database access
http://codeinthehole.com/writing/disable-database-access-when-writing-unit-
tests-in-django/
"""
no_database = curry(
    mock.patch, 'django.db.backends.util.CursorWrapper',
    mock.Mock(side_effect=DatabaseError))


def get_ldap_user(username):
    """ Retrieve LDAP user from the fake LDAP directory """
    dn = settings.AUTH_LDAP_USER_DN_TEMPLATE % {'user': username}
    return (dn, settings.DIRECTORY[dn])


def set_search_seed(username):
    """ Create the filterstr of the search_s seed part of the mocked
    ldap object """
    search_item = '(&'
    for item in settings.AUTH_LDAP_USER_OBJECTCLASS:
        search_item += '(objectClass=%s)' % item
    search_item += '(uid=%s))' % username
    return search_item


def set_request(uri, post=False, user=False, messages=False):
    """ Sets a request with RequestFactory """
    if post:
        if type(post) == bool:
            post = {}
        request = RequestFactory().post(uri, post)
    else:
        request = RequestFactory().get(uri)
    if user:
        request.user = user
    else:
        request.user = AnonymousUser()
    request.user.is_verified = lambda: True
    request.session = SessionStore()
    if messages:
        SessionMiddleware().process_request(request)
        MessageMiddleware().process_request(request)
    return request


class OkupyTestCase(TestCase):
    """
    Custon TestCase class, implements additional assert functions
    http://stackoverflow.com/questions/2897609/how-can-i-unit-test-django-
    messages
    """
    def _get_matches(self, response, text):
        """ Get messages that match the given text """
        messages = self._get_messages(response)
        if messages:
            matches = [m for m in messages if text == m.message]
            return matches
        else:
            self.fail('No messages found')

    def _get_messages(self, response):
        """ Get all messages from the context or the CookieStorage """
        try:
            messages = response.context['messages']
        except (TypeError, KeyError):
            try:
                messages = CookieStorage(response)._decode(
                    response.cookies['messages'].value)
            except KeyError:
                return
        return messages

    def assertMessageCount(self, response, expect_num):
        """
        Asserts that exactly the given number of messages have been sent.
        """
        messages = self._get_messages(response)
        if messages:
            actual_num = len(messages)
        else:
            actual_num = 0
        if actual_num != expect_num:
            self.fail('Message count was %d, expected %d' %
                     (actual_num, expect_num))

    def assertMessage(self, response, text, level=None):
        """
        Asserts that there is exactly one message containing the given text.
        """
        matches = self._get_matches(response, text)
        if len(matches) == 1:
            msg = matches[0]
            if level is not None and msg.level != level:
                self.fail('There was one matching message but with different '
                          'level: %s != %s' % (msg.level, level))
        elif len(matches) == 0:
            messages_str = ", ".join(
                '"%s"' % m for m in self._get_messages(response))
            self.fail('No message contained text "%s", messages were: %s' %
                     (text, messages_str))
        else:
            self.fail('Multiple messages contained text "%s": %s' %
                     (text, ", ".join(('"%s"' % m) for m in matches)))

    def assertNotMessage(self, response, text):
        """ Assert that no message contains the given text. """
        matches = self._get_matches(response, text)
        if len(matches) > 0:
            self.fail('Message(s) contained text "%s": %s' %
                     (text, ", ".join(('"%s"' % m) for m in matches)))
