from core.Module import Module
from core.LocalModule import LocalModule
import socket
import errno
import logging
log = logging.getLogger(__name__)
import traceback

class TCPClient(LocalModule):
    """
    Base async TCP class. Networked plugins should probably inherit from this module.
    """
    def __init__(self, host, port):
        """
        Local events registered:
            * send <data> - sends data.
            * close       - close the socket.
            * connect     - initialize the socket.
        """
        super(TCPClient, self).__init__()

        self.host = host
        self.port = port

        self.reads = []
        self.write_buffer = ''

        self.register_local('send', self.send)
        self.register_local('close', self.die)
        self.register_local('connect', self.init)

    def readable(self, client):
        """
        Callback for the readable socket. Receives 65535 bytes and will either pass it
        along or detect that the socket is closed.

        Local events raised:
            * closed          - indicates that the socket has been closed.
            * received <data> - indicates that data was received.
        """
        data = self.sock.recv(65535)
        if not data:
            self.closed = True
            self.trigger_local('closed')
            self.die()

        self.trigger_local('received', data)

    def writable(self, client):
        """
        Callback for the writable socket. If we're still connecting this means that
        the socket is now connected. If we are already connected we try to send everything
        in our send buffer. If the send buffer is empty then we mark the socket unwritable.

        Events raised:
            * fd_unwritable <sock> - indicates that the socket no longer needs to write.
            * fd_readable <sock>   - indicates that we want to read from the socket,
                                     raised when we connect.

        Local events raised:
            * connected - indicates that the socket has successfully connected.
        """
        if self.connecting:
            self.connecting = False

            self.trigger('fd_unwritable', self.sock)
            self.trigger('fd_readable', self.sock)
            self.trigger_local('connected')
        else:
            num_bytes = self.sock.send(self.write_buffer)
            self.write_buffer = self.write_buffer[num_bytes:]

            if not self.write_buffer or not num_bytes:
                self.write_buffer = ''
                self.trigger('fd_unwritable', self.sock)

    def exceptional(self, client):
        """
        Indicates that the socket is exceptional. Tries to restart it.
        """
        self.init()

    def send(self, data):
        """
        Call back for the local send event. Adds the data to the write_buffer.

        Events triggered:
            * fd_writable <sock> - indicates that we want to write on the socket.
        """
        self.write_buffer += data
        self.trigger('fd_writable', self.sock)

    def init(self):
        """
        Initializes and connects the socket. It will first die() to ensure the socket
        is closed already.
        
        Events raised:
            * fd_writable <sock>    - indicates that the socket is writable.
            * fd_exceptional <sock> - indicates that we want to know when the socket is
                                      exceptional.

        Local events raised:
            * init - indicates that we've just initialized the socket.

        Events registered:
            * fd_<sock>_readable <sock>    - raised when the socket is readable.
            * fd_<sock>_writable <sock>    - raised when the socket is writable.
            * fd_<sock>_exceptional <sock> - raised when the socket is exceptional.
        """
        self.die()

        self.closed = False

        self.sock = socket.socket()
        self.sock.setblocking(False)

        try:
            self.sock.connect((self.host, self.port))
        except socket.error as err:
            if errno.errorcode[err.errno] != 'EINPROGRESS':
                self.die()
                return

        self.connecting = True

        self.register('fd_%s_readable' % self.sock, self.readable)
        self.register('fd_%s_writable' % self.sock, self.writable)
        self.register('fd_%s_exceptional' % self.sock, self.exceptional)

        self.trigger('fd_writable', self.sock)
        self.trigger('fd_exceptional', self.sock)

        self.trigger_local('init')

    def die(self):
        """
        Destroys a socket and closes the connection.

        Events raised:
            * fd_unreadable <sock>    - indicates that we don't want to read from the socket
                                        anymore.
            * fd_unwritable <sock>    - indicates that we don't want to write to the socket.
            * fd_unexceptional <sock> - indicates that we don't want to know when the socket
                                        is exceptional.

        Local events raised:
            * die - indicates that the socket was just closed.

        Events unregistered:
            * fd_<sock>_readable <sock>    - raised when the socket is readable.
            * fd_<sock>_writable <sock>    - raised when the socket is writable.
            * fd_<sock>_exceptional <sock> - raised when the socket is exceptional.
        """
        if not hasattr(self, 'sock') or not self.sock:
            return
        
        self.closed = True

        self.trigger('fd_unreadable', self.sock)
        self.trigger('fd_unwritable', self.sock)
        self.trigger('fd_unexceptional', self.sock)

        self.unregister('fd_%s_readable' % self.sock, self.readable)
        self.unregister('fd_%s_writable' % self.sock, self.writable)
        self.unregister('fd_%s_exceptional' % self.sock, self.exceptional)

        self.sock = None
        self.connecting = False

        self.trigger_local('die')
