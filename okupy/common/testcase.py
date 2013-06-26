# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.test import TestCase
from django.contrib.messages.storage.cookie import CookieStorage

class OkupyTestCase(TestCase):
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
                messages = CookieStorage(response)._decode(response.cookies['messages'].value)
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
            messages_str = ", ".join('"%s"' % m for m in self._get_messages(response))
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
