from core.Module import Module
from modules.Tor.TorLineClient import TorLineClient

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse
import re

import logging
log = logging.getLogger(__name__)

# Regexes that we use for parsing headers and the HTTP status.
code_re = re.compile(r'^HTTP/(?P<version>[0-9]\.[0-9]) (?P<status>[0-9]{3}) (?P<reason>.*)$')
header_re = re.compile(r'^(?P<header>[A-Za-z-]+): (?P<value>.*)$')

class HTTPRequest(TorLineClient):
    """
    Tor-based HTTP client.
    """

    def __init__(self, url, directory=False, data=None, headers=None, method='GET'):
        """
        Local events registered:
            * connected     - the socket has connected.
            * line <line>   - indicates that a line has been received.
            * chunk <chunk> - indicates that a chunk has been received.
            * line_closed   - indicates that the socket has closed and all data has
                              been read.
        """
        self.method = method
        self.headers = headers or {}
        self.data = data

        self.res = {}

        self.response_headers = {}
        self.response_status = 0

        self.url = urlparse.urlparse(url)
        self.port = self.url.port or 80 if self.url.scheme == 'http' else 443

        super(HTTPRequest, self).__init__((self.url.hostname, self.port), directory)

        self.register_local('connected', self.connected)
        self.register_local('line', self.parse)
        self.register_local('chunk', self.parse_chunk)
        self.register_local('line_closed', self.tcp_closed)

    def tcp_closed(self):
        """
        The socket is closed.
        
        Local events raised:
            * done - indicates that the HTTP request has completed.
        """
        self.trigger_local('done')

    def module_load(self):
        """
        On module load begin connecting.
        
        Local events raised:
            * connect - begin the connection.
        """
        self.trigger_local('connect')

    def connected(self):
        """
        Excecuted once the socket is connected. Will send the HTTP request.
        
        Local events raised:
            * send <data> - sends data on the socket.
        """
        self.trigger_local('send', self.build_http())
        self.chunked = False

    def parse(self, line):
        """
        Parse an HTTP response.
        
        Events raised:
            TODO: THESE SHOULD BE LOCAL EVENTS

            * headers <headers> - headers have been received.
            * status <response> - HTTP status has been received.

        Local events raised:
            * die               - closes the HTTP request.

        """

        # If we haven't gotten the status yet, we try to parse that. If the status line
        # doesn't parse we close the connection.
        if 'status' not in self.res:
            line = code_re.search(line)

            if not line:
                log.error('could not parse http status')
                self.trigger_local('die')
                return

            self.res['status'] = line.group('status')
            self.res['version'] = line.group('version')
            self.res['reason'] = line.group('reason')

            log.debug('got status line: %s' % self.res)
            self.trigger('status', self.res)

        # If we have the status, then we start parsing the headers.
        elif 'status' in self.res and 'num_bytes' not in self.res:
            if 'headers' not in self.res:
                self.res['headers'] = {}

            # If we received a blank line, that means the headers have all been read.
            # We also attempt to parse out the content length and switch to chunked reads.
            if not line:
                self.chunked = True
                log.debug('got all headers, reading body')
                self.trigger('headers', self.res['headers'])
                self.content_length()
                return

            header = header_re.search(line)

            if not header:
                log.error('could not parse header')
                self.trigger_local('die')
                return

            h, v = self.header_caps(header.group('header')), header.group('value')
            self.res['headers'][h] = v
            log.debug('got header %s: %s' % (h, v))

    def parse_chunk(self, chunk):
        """
        Track the content length and forward on the data, closes the connection if we have
        read all the way to the specified content-length, if any.

        Local events raised:
            * data <chunk> - HTTP body data ready.
            * die          - close the connection.
        """
        self.res['num_bytes'] += len(chunk)

        self.trigger_local('data', chunk)

        if 'content-length' not in self.res:
            return
            
        if self.res['content-length'] <= self.res['num_bytes']:
            log.info('all bytes read, closing connection.')
            self.die()
            # self.trigger_local('done')

    def content_length(self):
        """
        Parse the content-length header, if it exists.

        Local events raised:
            * die - close the connection.
        """
        self.res['num_bytes'] = 0

        if 'Content-Length' in self.res['headers']:
            try:
                self.res['content-length'] = int(self.res['headers']['Content-Length'])
            except ValueError:
                log.error('could not parse content-length')
                self.trigger_local('die')
                return

    def build_http(self):
        """
        Builds an HTTP request out of the method, path, headers, and data.
        """
        full_path = self.url.path
        if self.url.query:
            full_path += '?' + self.url.query
 
        request = '{method} {path} HTTP/1.1\r\n'.format(method=self.method,
            path=full_path)

        self.headers = dict(map(lambda x, y: [ self.header_caps(x), y ],
            self.headers.iteritems()))

        if 'Host' not in self.headers:
            self.headers['Host'] = self.url.hostname

        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = ''

        for header in self.headers:
            request += '{header}: {value}\r\n'.format(header=header,
                value=self.headers[header])
        request += '\r\n'

        return request

    def header_caps(self, header):
        """
        Capitalize the headers so they look standard.
        """
        header = header.split('-')
        _header = []

        for h in header:
            if len(h) == 2:
                _header.append(h.upper())
            else:
                _header.append(h[0].upper() + h[1:].lower())

        return '-'.join(_header)

class HTTPClient(Module):
    """
    HTTPClient "factory" module. Dispatches HTTP requests.
    """
    dependencies = [ 'Select' ]

    def module_load(self):
        """
        Events registered:
            * http_get <url> [headers] - perform an HTTP request.
        """
        self.register('http_get', self.get)

    def get(self, url, headers=None, directory=False):
        """
        Dispatches HTTP request.
        """
        request = HTTPRequest(url, headers=headers, directory=directory)
        request.init_module()
        return request
