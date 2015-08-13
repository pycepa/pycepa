from core.LocalModule import LocalModule
import random
import logging
log = logging.getLogger(__name__)

class TorSocket(LocalModule):
    dependencies = ['Tor.Proxy']

    def __init__(self, directory=False):
        super(TorSocket, self).__init__()

        self.stream_id = random.randint(1, 65535)
        self.register('tor_directory_stream_%s_recv' % self.stream_id, self.recv)
        self.register('tor_directory_stream_%s_connected' % self.stream_id,
            self.connected)

        self.connect(None)

    def connected(self):
        self.send('GET / HTTP/1.1')

    def connect(self, host):
        self.trigger_avail('tor_init_directory_stream', self.stream_id)

    def recv(self, data):
        log.debug('Received line: ' + data)

    def send(self, data):
        self.trigger('tor_directory_stream_%s_send' % self.stream_id, data)
