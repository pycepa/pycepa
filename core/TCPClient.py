from core.Module import Module
from core.LocalModule import LocalModule
import socket
import errno
import logging
log = logging.getLogger(__name__)

class TCPClient(LocalModule):
    def __init__(self, host, port):
        super(TCPClient, self).__init__()

        self.host = host
        self.port = port

        self.reads = []
        self.write_buffer = ''

        self.register_local('send', self.send)
        self.register_local('close', self.die)
        self.register_local('connect', self.init)

    def readable(self, client):
        data = self.sock.recv(65535)
        if not data:
            self.closed = True
            self.trigger_local('closed')
            self.die()

        self.trigger_local('received', data)

    def writable(self, client):
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
        self.init()

    def send(self, data):
        self.write_buffer += data
        self.trigger('fd_writable', self.sock)

    def init(self):
        self.die()

        self.closed = False

        self.sock = socket.socket()
        self.sock.setblocking(False)

        code = self.sock.connect_ex((self.host, self.port))
        if errno.errorcode[code] != 'EINPROGRESS':
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
