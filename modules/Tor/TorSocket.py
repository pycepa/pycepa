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
            * tor_directory_stream_<stream_id>_recv <data> - received data from Tor stream.
            * tor_directory_stream_<stream_id>_connected   - initial connection through Tor
                                                             completed.
            * tor_directory_stream_<stream_id>_closed      - indicates that the stream has
                                                             closed.

        Local events registered:
            * send <data> - send data through the stream.
        """
        super(TorSocket, self).__init__()

        self.stream_id = random.randint(1, 65535)
        self.register('tor_directory_stream_%s_recv' % self.stream_id, self.recv)
        self.register('tor_directory_stream_%s_connected' % self.stream_id,
            self._connected)
        self.register('tor_directory_stream_%s_closed' % self.stream_id, self.die)
        self.register_local('send', self.send)

        self.closed = False

        self.connect()

    def die(self, stream_id=None):
        """
        Closes the stream.
        
        Local events raised:
            * closed - indicates that the socket has closed.
        """
        self.closed = True
        self.trigger_local('closed')

    def _connected(self, stream_id):
        """
        Indicates that the socket has connected.

        Local events raised:
            * connected - socket connected.
        """
        self.trigger_local('connected')

    def connect(self):
        """
        Initialize directory stream.

        Events raised:
            * tor_init_directory_stream <stream_id> - create a directory stream with the
                                                      given stream id.
        """
        self.trigger_avail('tor_init_directory_stream', self.stream_id)

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
            * tor_directory_stream_<stream_id>_send <data> - send data through stream.
        """
        self.trigger('tor_directory_stream_%s_send' % self.stream_id, data)
