from core.Module import Module
import socket

import logging
log = logging.getLogger(__name__)

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
    dependencies = [ 'HTTPClient' ]

    def module_load(self):
        dir_serv = authorities[0]

        self.or_port = dir_serv['or_port']
        self.ip_address = dir_serv['ip_address']
        self.dir_port = dir_serv['dir_port']

        self.retrieved_consensus = False
        self.consensus = ''
        self.mds = []

        self.wanted_routers = []

        self.register('tor_get_router', self.get_router)

    def get_router(self, flags):
        self.wanted_routers.append(flags)

        if not self.retrieved_consensus:
            self.retrieve_consensus()
            self.retrieved_consensus = True
            return
        else:
            for md in self.mds:
                if not self.check_flags(md):
                    continue
                break
            
    def check_flags(self, md):
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
            self.found(f, md)

    def found(self, router, md):
        chunks = [ '' ]

        def chunk(c):
            chunks[0] += c
            log.debug(c)

        def done():
            log.debug('done')
            self.trigger('tor_got_md_%s' % router, md)

        self.do_http('tor/server/d/%s.z' % (md['descriptor_id'] + '=').decode('base64').encode('hex'), chunk, done)

    def retrieve_consensus(self):
        cmd = 'status-vote/current/consensus'
        self.do_http(cmd, self.chunk, self.parse_mds)

    def do_http(self, cmd, chunk, done):
        url = 'http://%s:%d/tor/%s' % (self.ip_address, self.dir_port, cmd)

        log.info('requesting %s from %s' % (cmd, self.ip_address))

        request = self.trigger('http_get', url)
        request.register_local('chunk', chunk)
        request.register_local('done', done)

    def chunk(self, c):
        self.consensus += c

    def parse_mds(self):
        log.info('got consensus')

        md = None

        for line in self.consensus.split('\n'):
            line = line.split()

            if len(line) < 2:
                continue
            elif line[0] == 'r' and len(line) == 9:
                md = {
                    'name': line[1],
                    'descriptor_id': line[2],
                    'ip': line[6],
                    'or_port': int(line[7]),
                    'dir_port': int(line[8])
                }
            elif line[0] == 's' and md:
                md['flags'] = line[1:]
                # log.debug('got microdescriptor: %s' % md)
                self.mds.append(md)
                self.check_flags(md)
                md = None

        self.trigger('tor_parsed_mds')
