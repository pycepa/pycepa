from core.Module import Module
import socket

import logging
log = logging.getLogger(__name__)

# default directory authorities
authorities = [
    {
        "name": "tor26",
        "or_port": 443,
        "ip": "86.59.21.38",
        "dir_port": 80
    },
    {
        "or_port": 443,
        "ip": "194.109.206.212",
        "dir_port": 80
    }
]

class DirServ(Module):
    """
    Requests network information from directory servers.
    """
    dependencies = [ 'HTTPClient' ]

    def module_load(self):
        """
        Events registered:
            * tor_get_router <flags>     - request a router with the given flags.
            * tor_parsed_router <router> - parsed a router from the server descriptors
                                           document.
        """
        dir_serv = authorities[0]

        self.or_port = dir_serv['or_port']
        self.ip_address = dir_serv['ip']
        self.dir_port = dir_serv['dir_port']

        self.retrieved_consensus = False
        self.consensus = ''
        self.mds = []
        self.consensus_buffer = ''
        self.server_buffer = ''

        self.wanted_routers = []

        self.register('tor_get_router', self.get_router)
        self.register('tor_parsed_router', self.parsed_router)
        self.register('tor_parsed_md', self.check_flags)

    def get_router(self, flags):
        """
        Retrieve an OR matching the given flags.
        """
        self.wanted_routers.append(flags)

        if not self.retrieved_consensus:
            self.retrieve_servers()
            self.retrieve_consensus()
            self.retrieved_consensus = True
            return
        else:
            for md in self.mds:
                if not self.check_flags(md):
                    continue
                break
            
    def check_flags(self, md):
        """
        Hunt down an OR with the requested flags.
        """
        use = True
        found = []

        for flags in self.wanted_routers:
            use = True

            for flag in flags:
                if flag not in md['flags']:
                    use = False

            if use:
                found.append(flags)

        for f in found:
            log.info('found router with flags %s: %s' % (f, md))
            self.wanted_routers.remove(f)
            # self.found(f, md)

    def retrieve_servers(self):
        """
        Retrieve network server document.
        """
        cmd = 'server/all'
        self.do_http(cmd, self.server_chunk, self.parsed_servers)

    def retrieve_consensus(self):
        """
        Retrieve network consensus document.
        """
        cmd = 'status-vote/current/consensus'
        self.do_http(cmd, self.consensus_chunk, self.parsed_consensus)

    def do_http(self, cmd, chunk=None, done=None):
        """
        Opens an HTTP request over Tor.

        Events raised:
            * http_get <url> [headers] - opens HTTP request over tor.

        Request local events raised:
            * chunk <chunk> - chunk received.
            * done          - the request completed.
        """
        url = 'http://%s:%d/tor/%s' % (self.ip_address, self.dir_port, cmd)

        log.info('requesting %s from %s' % (cmd, self.ip_address))

        request = self.trigger('http_get', url)
        if chunk:
            request.register_local('chunk', chunk)
        if done:
            request.register_local('done', done)

    def consensus_chunk(self, c):
        """
        Received chunk of consensus data.
        """
        self.consensus_buffer += c
        c = self.consensus_buffer.split('\n')
        c, self.consensus_buffer = c[:-1], c[-1]
        for line in c:
            self.parse_consensus_line(line)

    def parse_consensus_line(self, line):
        """
        Parse microdescriptors from the consensus:

        Events raised:
            * tor_parsed_md - indicates that we've parsed a microdescriptor..
        """
        line = line.split()

        if len(line) < 2:
            return
        elif line[0] == 'r' and len(line) == 9:
            if hasattr(self, 'md'):
                self.trigger('tor_parsed_md', self.md)
            
            self.md = {
                'name': line[1],
                'identity': line[2],
                'digest': line[3],
                'publication': line[4:6],
                'ip': line[6],
                'or_port': int(line[7]),
                'dir_port': int(line[8])
            }

        if not hasattr(self, 'md'):
            return

        if line[0] == 's':
            self.md['flags'] = line[1:]
            # log.debug('got microdescriptor: %s' % md)

    def parsed_consensus(self):
        if hasattr(self, 'md'):
            self.trigger('tor_parsed_md', self.md)

        self.trigger('tor_parsed_mds')

    def server_chunk(self, c):
        """
        Received chunk of consensus data.
        """
        self.server_buffer += c
        c = self.server_buffer.split('\n')
        c, self.server_buffer = c[:-1], c[-1]
        for line in c:
            self.parse_server_line(line)

    def parse_server_line(self, line):
        """
        Parse microdescriptors from the consensus.

        Events raised:
            * tor_parsed_router - indicates that we've parsed the an router.
        """
        line = line.split()
        if not line:
            return

        if line[0] == 'router' and len(line) == 6:
            if hasattr(self, 'router'):
                self.trigger('tor_parsed_router', self.router)

            self.reading_key = ''
            self.router = {
                'name': line[1],
                'ip': line[2],
                'or_port': line[3],
                'socks_port': line[4],
                'dir_port': line[5]
            }

        if not hasattr(self, 'router') or not self.router:
            return

        if line[0] == 'fingerprint' and len(line) == 11:
            self.router['fingerprint'] = line[1:]
        elif line[0] in [ 'onion-key', 'signing-key', 'router-signature',
            'dir-identity-key', 'dir-signing-key' ]:
            self.reading_key = line[0]
            self.router[line[0]] = ''
        elif line[0] == 'ntor-onion-key' and len(line) == 2:
            self.router['ntor-onion-key'] = line[1]
        elif line[0] == 'reject' and len(line) == 2:
            if 'reject' not in self.router:
                self.router['reject'] = []
            self.router['reject'].append(line[1])
        elif line[0] == 'accept' and len(line) == 2:
            if 'accept' not in self.router:
                self.router['accept'] = []
            self.router['accept'].append(line[1])

        if hasattr(self, 'reading_key') and self.reading_key:
            if not self.router[self.reading_key] and line[0] != '-----BEGIN':
                return
            elif len(line[0]) != 64 and line[0] != '-----END' and line[0] != '-----BEGIN':
                return

            self.router[self.reading_key] += ' '.join(line)
            if line[0] == '-----END':
                self.reading_key = ''
            else:
                self.router[self.reading_key] += '\n'

    def parsed_servers(self):
        """
        Parsed entire server document.

        Events raised:
            * tor_parsed_routers - indicates that we've parsed all of the servers.
        """
        if hasattr(self, 'router'):
            self.trigger('tor_parsed_router', self.router)
        self.trigger('tor_parsed_routers')

    def parsed_router(self, router):
        log.debug('Parsed router: %s' % router)
