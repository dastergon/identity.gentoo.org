# -*- coding: utf-8 -*-

from django.test import TestCase

class OkupyTestCase(TestCase):
    def assertMessageCount(self, response, expect_num):
        """
        Asserts that exactly the given number of messages have been sent.
        """

        try:
            messages = response.context['messages']
            actual_num = len(response.context['messages'])
        except TypeError:
            actual_num = 0
        if actual_num != expect_num:
            self.fail('Message count was %d, expected %d' %
                (actual_num, expect_num))

    def assertMessage(self, response, text, level=None):
        """
        Asserts that there is exactly one message containing the given text.
        """

        try:
            messages = response.context['messages']
        except TypeError:
            self.fail('No messages found')

        matches = [m for m in messages if text == m.message]

        if len(matches) == 1:
            msg = matches[0]
            if level is not None and msg.level != level:
                self.fail('There was one matching message but with different '
                    'level: %s != %s' % (msg.level, level))

            return

        elif len(matches) == 0:
            messages_str = ", ".join('"%s"' % m for m in messages)
            self.fail('No message has text "%s", messages were: %s' %
                (text, messages_str))
        else:
            self.fail('Multiple messages have text "%s": %s' %
                (text, ", ".join(('"%s"' % m) for m in matches)))

    def assertNotMessage(self, response, text):
        """ Assert that no message contains the given text. """

        try:
            messages = response.context['messages']
        except TypeError:
            self.fail('No messages found')

        matches = [m for m in messages if text == m.message]

        if len(matches) > 0:
            self.fail('Message(s) found"%s": %s' %
                (text, ", ".join(('"%s"' % m) for m in matches)))
