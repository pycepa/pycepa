from core.TCPClient import TCPClient
import ssl
import logging
import socket
log = logging.getLogger(__name__)

class TLSClient(TCPClient):
    def __init__(self, host, port):
        super(TLSClient, self).__init__(host, port)
        self.register_local('init', self.do_ssl)
        self.register_local('connected', self.do_handshake)

    def readable(self, client):
        if not self.handshook:
            self.do_handshake()

        if not self.handshook:
            return

        try:
            super(TLSClient, self).readable(client)
        except ssl.SSLError as err:
            if err.args[0] != ssl.SSL_ERROR_WANT_READ:
                self.die()
        except socket.error:
            self.die()

    def do_ssl(self):
        self.handshook = False

        self.trigger('fd_unreadable', self.sock)
        self.trigger('fd_unwritable', self.sock)
        self.trigger('fd_unexceptional', self.sock)

        self.sock = ssl.wrap_socket(self.sock, ssl_version=ssl.PROTOCOL_TLSv1_2,
            do_handshake_on_connect=False)

        self.register('fd_%s_readable' % self.sock, self.readable)
        self.register('fd_%s_writable' % self.sock, self.writable)
        self.register('fd_%s_exceptional' % self.sock, self.exceptional)

        self.trigger('fd_writable', self.sock)

    def do_handshake(self):
        try:
            self.sock.do_handshake()
            self.handshook = True
            self.trigger_local('handshook')
        except ssl.SSLError as err:
            if err.args[0] != ssl.SSL_ERROR_WANT_READ:
                self.die()
        except socket.error:
            self.die()
