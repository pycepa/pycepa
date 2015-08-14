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
            * init - raised when the socket is initialised.
            * connected - raised when the socket is connected.
        """
        super(TLSClient, self).__init__(host, port)
        self.register_local('init', self.do_ssl)
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
            print traceback.print_exc(e)
            log.error('socket error: %s' % e)
            self.die()

    def do_ssl(self):
        """
        Initializes the TLS socket.
        
        Events raised:
            * fd_unreadable <sock>    - indicates that we don't want to read from this
                                        socket.
            * fd_unwritable <sock>    - indicates that we don't want to write to this
                                        socket.
            * fd_unexceptional <sock> - indicates that we don't want to listen for
                                        exceptional socket events. 
            * fd_writable <sock>      - indicates that we want to write to the socket.

        Events registered:
            * fd_<sock>_readable <sock>    - raised when the socket is readable.
            * fd_<sock>_writable <sock>    - raised when the socket is writable.
            * fd_<sock>_exceptional <sock> - raised when the socket is exceptional.
        """
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
