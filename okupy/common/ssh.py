# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

from django.conf import settings

import paramiko

from io import BytesIO

import asyncore
import socket
import threading


LISTEN_BACKLOG = 20


class SSHServer(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return 'publickey'

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        return False

    def check_channel_exec_request(self, channel, command):
        channel.send('Not yet implemented, sorry.\r\n')
        channel.shutdown(2)
        channel.close()
        return True

    def check_channel_shell_request(self, channel):
        channel.send('Not yet implemented, sorry.\r\n')
        channel.shutdown(2)
        channel.close()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
            pixelwidth, pixelheight, modes):
        return True


class SSHDispatcher(asyncore.dispatcher):
    def __init__(self, server_key):
        asyncore.dispatcher.__init__(self)
        self._server_key = server_key

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(settings.SSH_BIND)
        self.listen(LISTEN_BACKLOG)

    def handle_accepted(self, conn, addr):
        t = paramiko.Transport(conn)
        t.add_server_key(self._server_key)
        # we need a dummy Event to make it non-blocking
        # but we don't really need to play with it
        t.start_server(event=threading.Event(), server=SSHServer())

    # python<3.2 compat
    def handle_accept(self):
        ret = self.accept()
        if ret is not None:
            self.handle_accepted(*ret)


def ssh_main():
    server_key = paramiko.RSAKey(file_obj=BytesIO(settings.SSH_SERVER_KEY))

    disp = SSHDispatcher(server_key)
    asyncore.loop()
    raise SystemError('SSH server loop exited')
