# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings
from django.test import TestCase
from django.test.utils import override_settings

import base64
import socket

import paramiko

from okupy import OkupyError
from okupy.common.ssh import ssh_handler, SSHServer
from okupy.tests.vars import TEST_SSH_KEY_FOR_NO_USER


@override_settings(SSH_HANDLERS={})
class SSHUnitTests(TestCase):
    def setUp(self):
        self._key = paramiko.RSAKey(
            data=base64.b64decode(TEST_SSH_KEY_FOR_NO_USER))
        self._server = SSHServer()

    def test_ssh_handler_decorator_works(self):
        @ssh_handler
        def test(key):
            pass

        self.assertEqual(settings.SSH_HANDLERS.get('test'), test)

    def test_noarg_handler_works(self):
        @ssh_handler
        def noarg(key):
            return 'yay'

        self.assertEqual(
            self._server.check_auth_publickey('noarg', self._key),
            paramiko.AUTH_SUCCESSFUL)

    def test_failure_is_propagated_properly(self):
        @ssh_handler
        def failing(key):
            return None

        self.assertEqual(
            self._server.check_auth_publickey('failing', self._key),
            paramiko.AUTH_FAILED)

    def test_argument_splitting_works(self):
        @ssh_handler
        def twoarg(a, b, key):
            if a == '1' and b == '2':
                return 'yay'
            else:
                return None

        self.assertEqual(
            self._server.check_auth_publickey('twoarg+1+2', self._key),
            paramiko.AUTH_SUCCESSFUL)

    def test_default_arguments_work(self):
        @ssh_handler
        def oneortwoarg(a, b='3', key=None):
            if not key:
                raise ValueError('key must not be None')
            if a == '1' and b == '3':
                return 'yay'
            else:
                return None

        self.assertEqual(
            self._server.check_auth_publickey('oneortwoarg+1', self._key),
            paramiko.AUTH_SUCCESSFUL)

    def test_wrong_command_returns_failure(self):
        @ssh_handler
        def somehandler(key):
            return 'er?'

        self.assertEqual(
            self._server.check_auth_publickey('otherhandler', self._key),
            paramiko.AUTH_FAILED)

    def test_missing_arguments_return_failure(self):
        @ssh_handler
        def onearg(arg, key):
            return 'er?'

        self.assertEqual(
            self._server.check_auth_publickey('onearg', self._key),
            paramiko.AUTH_FAILED)

    def test_too_many_arguments_return_failure(self):
        @ssh_handler
        def onearg(arg, key):
            return 'er?'

        self.assertEqual(
            self._server.check_auth_publickey('onearg+1+2', self._key),
            paramiko.AUTH_FAILED)

    def test_typeerror_is_propagated_properly(self):
        @ssh_handler
        def onearg(key):
            raise TypeError

        self.assertRaises(TypeError,
            self._server.check_auth_publickey, 'onearg', self._key)

    def test_result_caching_works(self):
        class Cache(object):
            def __init__(self):
                self.first = True

            def __call__(self, key):
                if self.first:
                    self.first = False
                    return 'yay'
                else:
                    return None

        cache = Cache()
        @ssh_handler
        def cached(key):
            return cache(key)

        if (self._server.check_auth_publickey('cached', self._key)
                != paramiko.AUTH_SUCCESSFUL):
            raise OkupyError('Test prerequisite failed')
        self.assertEqual(
            self._server.check_auth_publickey('cached', self._key),
            paramiko.AUTH_SUCCESSFUL)

    def test_message_is_printed_to_exec_request(self):
        @ssh_handler
        def noarg(key):
            return 'test-message'

        if (self._server.check_auth_publickey('noarg', self._key)
                != paramiko.AUTH_SUCCESSFUL):
            raise OkupyError('Test prerequisite failed')

        s1, s2 = socket.socketpair()
        self.assertTrue(self._server.check_channel_exec_request(s1, ':'))
        self.assertEqual(s2.makefile().read().rstrip(), 'test-message')

    def test_message_is_printed_to_shell_request(self):
        @ssh_handler
        def noarg(key):
            return 'test-message'

        if (self._server.check_auth_publickey('noarg', self._key)
                != paramiko.AUTH_SUCCESSFUL):
            raise OkupyError('Test prerequisite failed')

        s1, s2 = socket.socketpair()
        self.assertTrue(self._server.check_channel_shell_request(s1))
        self.assertEqual(s2.makefile().read().rstrip(), 'test-message')

    def test_cache_is_invalidated_after_channel_request(self):
        class Cache(object):
            def __init__(self):
                self.first = True

            def __call__(self, key):
                if self.first:
                    self.first = False
                    return 'test-message'
                else:
                    return None

        cache = Cache()
        @ssh_handler
        def cached(key):
            return cache(key)

        if (self._server.check_auth_publickey('cached', self._key)
                != paramiko.AUTH_SUCCESSFUL):
            raise OkupyError('Test prerequisite failed')

        s1, s2 = socket.socketpair()
        if not self._server.check_channel_shell_request(s1):
            raise OkupyError('Test prerequisite failed')
        if s2.makefile().read().rstrip() != 'test-message':
            raise OkupyError('Test prerequisite failed')

        self.assertEqual(
            self._server.check_auth_publickey('cached', self._key),
            paramiko.AUTH_FAILED)
