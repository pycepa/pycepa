from core.Module import Module
from modules.Tor.TorLineClient import TorLineClient
import urlparse
import re

import logging
log = logging.getLogger(__name__)

code_re = re.compile(r'^HTTP/(?P<version>[0-9]\.[0-9]) (?P<status>[0-9]{3}) (?P<reason>.*)$')
header_re = re.compile(r'^(?P<header>[A-Za-z-]+): (?P<value>.*)$')

class HTTPRequest(TorLineClient):
    def __init__(self, url, data=None, headers=None, method='GET'):
        self.method = method
        self.headers = headers or {}
        self.data = data

        self.res = {}

        self.response_headers = {}
        self.response_status = 0

        self.url = urlparse.urlparse(url)
        self.port = self.url.port or 80 if self.url.scheme == 'http' else 443

        super(HTTPRequest, self).__init__(self.url.hostname, self.port)

        self.register_local('connected', self.connected)
        self.register_local('line', self.parse)
        self.register_local('chunk', self.parse_chunk)
        self.register_local('line_closed', self.tcp_closed)

    def tcp_closed(self):
        self.trigger_local('done')

    def module_load(self):
        self.trigger_local('connect')

    def connected(self):
        self.trigger_local('send', self.build_http())
        self.chunked = False

    def parse(self, line):
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
        elif 'status' in self.res and 'num_bytes' not in self.res:
            if 'headers' not in self.res:
                self.res['headers'] = {}

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
        self.res['num_bytes'] += len(chunk)

        self.trigger_local('data')

        if 'content-length' in self.res and self.res['content-length'] <= self.res['num_bytes']:
            log.info('all bytes read, closing connection.')
            self.trigger_local('done')
            self.die()

    def content_length(self):
        self.res['num_bytes'] = 0

        if 'Content-Length' in self.res['headers']:
            try:
                self.res['content-length'] = int(self.res['headers']['Content-Length'])
            except ValueError:
                log.error('could not parse content-length')
                self.trigger_local('die')
                return

    def build_http(self):
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
        header = header.split('-')
        _header = []

        for h in header:
            if len(h) == 2:
                _header.append(h.upper())
            else:
                _header.append(h[0].upper() + h[1:].lower())

        return '-'.join(_header)

class HTTPClient(Module):
    dependencies = [ 'Select' ]

    def module_load(self):
        self.register('http_get', self.get)

    def get(self, url, headers=None):
        request = HTTPRequest(url, headers=headers)
        request.init_module()
        return request
