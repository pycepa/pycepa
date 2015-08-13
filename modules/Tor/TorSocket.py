from core.LocalModule import LocalModule
import random
import logging
log = logging.getLogger(__name__)

class TorSocket(LocalModule):
    dependencies = ['Tor.Proxy']

    def __init__(self, hostname, port, directory=False):
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
        self.closed = True
        self.trigger_local('closed')

    def _connected(self, stream_id):
        self.trigger_local('connected')

    def connect(self):
        self.trigger_avail('tor_init_directory_stream', self.stream_id)

    def recv(self, data):
        self.trigger_local('received', data)

    def send(self, data):
        self.trigger('tor_directory_stream_%s_send' % self.stream_id, data)
