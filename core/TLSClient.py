from core.TCPClient import TCPClient
import ssl
import logging
import socket
log = logging.getLogger(__name__)
import traceback

class TLSClient(TCPClient):
    """
    Variation of the TCPClient that supports TLS.
    """

    def __init__(self, host, port):
        """
        Local events registered:
            * setup - raised when the socket is about to connect.
            * connected - raised when the socket is connected.
        """
        super(TLSClient, self).__init__(host, port)
        self.context = None
        self.register_local('setup', self.do_ssl)
        self.register_local('connected', self.do_handshake)

    def readable(self, client):
        """
        Callback when the socket is readable. If we need to do the TLS handshake, it will
        start that, otherwise it will attempt to read data from the socket. If we need more
        data to decrypt the data, it will save and continue.

        See core.TCPClient.readable() for more information.
        """
        if not self.handshook:
            self.do_handshake()

        if not self.handshook:
            return

        try:
            super(TLSClient, self).readable(client)
        except ssl.SSLError as err:
            if err.args[0] != ssl.SSL_ERROR_WANT_READ:
                self.die()
        except socket.error as e:
            print(traceback.print_exc(e))
            log.error('socket error: %s' % e)
            self.die()

    def do_ssl(self):
        """
        Setup the TLS socket context and wraps the socket.
        """
        _ssl = ssl
        if self.context:
            _ssl = self.context

        log.debug('Using SSL context: %s' % _ssl)
        self.sock = _ssl.wrap_socket(self.sock, do_handshake_on_connect=False)
        self.handshook = False

    def do_handshake(self):
        """
        Does the TLS handshake on a fresh connection.
        
        Local events raised:
            * handshook - indicates that the TLS handshake has completed and the socket
                          is ready for use.
        """
        try:
            self.sock.do_handshake()
            self.handshook = True
            self.trigger_local('handshook')
        except ssl.SSLError as err:
            if err.args[0] != ssl.SSL_ERROR_WANT_READ:
                self.die()
        except socket.error:
            self.die()
