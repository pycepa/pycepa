from modules.Tor.TorSocket import TorSocket
import logging
log = logging.getLogger(__name__)

class TorLineClient(TorSocket):
    """
    Variation of the TorSocket that can return lines instead of chunked data. To switch
    between chunked and line-based data, toggle the chunked variable.
    """
    def __init__(self, host=None, directory=False):
        """
        Local events registered:
            * received <data> - raised when data has been received from the socket.
        """
        super(TorLineClient, self).__init__(host=host, directory=directory)

        self.register_local('received', self.parse_line)
        self.register_local('closed', self._closed)
        self.data = ''
        self.chunked = False

    def _closed(self):
        """
        Forwards the closed event to line_closed if we don't have anything more
        to read.

        Local events raised:
            * line_closed - indicates that the socket is closed and we have read all
                            data
        """
        if not self.data or self.chunked:
            self.trigger_local('line_closed')

    def parse_line(self, data):
        """
        Parses a chunk. If in line-mode we will forward all complete lines and store the
        last line until we have a complete line. In chunked mode we just pass it along.

        Local events raised:
            * chunk <data> - raised when we receive a chunk.
            * line <line>  - raised when we receive a line.
            * line_closed  - raised when the socket is closed and we have read
                             all data.
        """
        if self.chunked:
            self.trigger_local('chunk', self.data + data)
            self.data = ''
        else:
            self.data += data

            lines = self.data.split('\r\n')
            lines, self.data = lines[:-1], lines[-1]

            for line in lines:
                self.trigger_local('line', line)

        if self.closed and not self.data and not self.chunked:
            self.trigger_local('line_closed')
