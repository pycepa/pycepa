from modules.Tor.TorSocket import TorSocket
import logging
log = logging.getLogger(__name__)

class TorLineClient(TorSocket):
    def __init__(self, host, port):
        super(TorLineClient, self).__init__(host, port)

        self.register_local('received', self.parse_line)
        self.data = ''
        self.chunked = False

    def parse_line(self, data):
        if self.chunked:
            self.trigger_local('chunk', self.data + data)
            self.data = ''
        else:
            self.data += data

            lines = self.data.split('\r\n')
            lines, self.data = lines[:-1], lines[-1]

            for line in lines:
                self.trigger_local('line', line)

        if self.closed and not self.data:
            self.trigger_local('line_closed')
