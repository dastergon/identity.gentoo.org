# -*- coding: utf-8 -*-

from django.test import TestCase

class OkupyTestCase(TestCase):
    def assertMessageCount(self, response, expect_num):
        """
        Asserts that exactly the given number of messages have been sent.
        """

        actual_num = len(response.context['messages'])
        if actual_num != expect_num:
            self.fail('Message count was %d, expected %d' %
                (actual_num, expect_num))

    def assertMessageContains(self, response, text, level=None):
        """
        Asserts that there is exactly one message containing the given text.
        """

        messages = response.context['messages']

        matches = [m for m in messages if text in m.message]

        if len(matches) == 1:
            msg = matches[0]
            if level is not None and msg.level != level:
                self.fail('There was one matching message but with different '
                    'level: %s != %s' % (msg.level, level))

            return

        elif len(matches) == 0:
            messages_str = ", ".join('"%s"' % m for m in messages)
            self.fail('No message contained text "%s", messages were: %s' %
                (text, messages_str))
        else:
            self.fail('Multiple messages contained text "%s": %s' %
                (text, ", ".join(('"%s"' % m) for m in matches)))

    def assertMessageNotContains(self, response, text):
        """ Assert that no message contains the given text. """

        messages = response.context['messages']

        matches = [m for m in messages if text in m.message]

        if len(matches) > 0:
            self.fail('Message(s) contained text "%s": %s' %
                (text, ", ".join(('"%s"' % m) for m in matches)))
