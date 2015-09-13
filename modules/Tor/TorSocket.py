from core.LocalModule import LocalModule
import random
import logging
log = logging.getLogger(__name__)

class TorSocket(LocalModule):
    """
    Base Tor socket. Used for writing Tor-based modules.
    """
    dependencies = ['Tor.Proxy']

    def __init__(self, hostname, port, directory=False):
        """
        Events registered:
            * tor_stream_<stream_id>_initialized - indicates that the stream is ready.
            * tor_stream_<stream_id>_connected   - initial connection through Tor completed.
            * tor_stream_<stream_id>_recv <data> - received data from Tor stream.
            * tor_stream_<stream_id>_closed      - indicates that the stream has closed.

        Local events registered:
            * send <data> - send data through the stream.
        """
        super(TorSocket, self).__init__()

        self.stream_id = random.randint(1, 65535)
        self.register('tor_stream_%s_initialized' % self.stream_id, self.initialized)
        self.register('tor_stream_%s_connected' % self.stream_id, self._connected)
        self.register('tor_stream_%s_recv' % self.stream_id, self.recv)
        self.register('tor_stream_%s_closed' % self.stream_id, self.die)
        self.register_local('send', self.send)

        self.closed = False
        self.connect()

    def initialized(self):
        """
        Indicates that the stream is ready to use.
        """
        if self.host:
            self.trigger('tor_stream_%d_init_tcp_stream' % self.stream_id, self.host[0],
                self.host[1])
        else:
            self.trigger('tor_stream_%d_init_directory_stream' % self.stream_id)

    def _connected(self, stream_id):
        """
        Indicates that the stream has connected.

        Local events raised:
            * connected - socket connected.
        """
        self.trigger_local('connected')

    def die(self, stream_id=None):
        """
        Closes the stream.
        
        Local events raised:
            * closed - indicates that the socket has closed.
        """
        self.closed = True
        self.trigger_local('closed')

    def recv(self, data):
        """
        Received data from stream.

        Local events raised:
            * received <data> - data received.
        """
        self.trigger_local('received', data)

    def send(self, data):
        """
        Send data through stream.
        
        Events raised:
            * tor_stream_<stream_id>_send <data> - send data through stream.
        """
        self.trigger('tor_stream_%s_send' % self.stream_id, data)

    def connect(self, host=None):
        """
        Initialize a stream. If no host is provided, it is assumed to be a directory stream.

        Events raised:
            * tor_init_stream <stream_id> - create a stream with the given stream id.
        """
        self.host = host
        self.trigger_avail('tor_init_stream', self.stream_id)
