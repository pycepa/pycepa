from core.TLSClient import TLSClient
from core.Module import Module
from core.LocalModule import LocalModule
from Crypto.Cipher import AES
from .cell import cell
from hashlib import sha1
import random
import struct
import logging
log = logging.getLogger(__name__)

class TorStream(LocalModule):
    def __init__(self, circuit):
        super(TorStream, self).__init__()

        self.closed  = False
        self.connected = False
        self.circuit = circuit
        self.data    = ''
        self.stream_id = random.randint(1, 65535)

        self.circuit.register_local('got_relay_for_%d_%d' % (self.circuit.circuit_id, 
            self.stream_id), self.got_relay)

    def gen_cell(self, command, data=None, digest=None):
        c = cell.Relay(self.circuit.circuit_id)
        c.init_relay({
            'relay_cmd': command,
            'stream_id': self.stream_id,
            'digest': digest or '\x00' * 4,
            'data': data
        })
        return c

    def send_cell(self, c):
        self.circuit.send_digest.update(c.get_str())
        c.data['digest'] = self.circuit.send_digest.digest()[:4]
        c.data = self.circuit.encrypt(c.get_str())
        self.circuit.trigger_local('send_cell', c)

    def connect(self, addr, port):
        data = '%s:%d\0%s' % (addr, port, struct.pack('>I', 0))
        self.send_cell(self.gen_cell(1, data))

    def got_relay(self, headers, data):
        log.info('%s %s' % (headers, data))
        if headers[0] == 4:
            self.connected = True
            self.trigger_local('connected', self.stream_id)
        elif headers[0] == 3:
            self.connected = False
            self.closed = True
        elif headers[0] == 2:
            log.debug(data)

    def send(self, data):
        self.send_cell(self.gen_cell(2, data))

class Circuit(LocalModule):
    def __init__(self, router):
        super(Circuit, self).__init__()
        self._events = router._events

        self.circuit_id = random.randint(1<<31, 2**31)

        self.established = False
        self.streams     = {}

        self.register_local('got_cell_CreatedFast', self.recv_cell)
        self.register_local('got_cell_Relay', self.recv_cell)

        log.info('initializing circuit id %d' % self.circuit_id)
        c = cell.CreateFast(circuit_id=self.circuit_id)
        self.Y = c.key_material

        self.trigger_local('send_cell', c)

    def crypt_init(self):
        k0 = self.Y + self.X

        K, i = '', 0
        while len(K) < 2*16 + 3*20:
            K += sha1(k0 + chr(i)).digest()
            i += 1

        KH = K[:20]
        DF = K[20:40]
        DB = K[40:60]
        KF = K[60:76]
        KB = K[76:92]

        self.Kfctr = 0
        def fctr():
            self.Kfctr += 1
            return ('%032x' % (self.Kfctr - 1)).decode('hex')

        self.Kbctr = 0
        def bctr():
            self.Kbctr += 1
            return ('%032x' % (self.Kbctr - 1)).decode('hex')

        self.send_digest = sha1(DF)
        self.recv_digest = sha1(DB)

        self.encrypt = AES.new(KF, AES.MODE_CTR, counter=fctr).encrypt
        self.decrypt = AES.new(KB, AES.MODE_CTR, counter=bctr).decrypt

    def connect(self):
        stream = TorStream(self)
        self.streams[stream.stream_id] = stream
        stream.register_local('connected', self.test)
        stream.connect('google.com', 80)

    def recv_cell(self, c):
        if c.circuit_id != self.circuit_id:
            return

        if isinstance(c, cell.CreatedFast):
            self.X = c.key_material
            self.crypt_init()
            self.established = True
            log.info('established circuit id %d.' % self.circuit_id)
            self.register_local('init_stream', self.connect)
            self.connect()
        elif isinstance(c, cell.Relay):
            data    = self.decrypt(c.data)
            headers = struct.unpack('>BHHIH', data[:11])
            data    = data[11:]

            if headers[2] in self.streams:
                self.trigger_local('got_relay_for_%d_%d' % (self.circuit_id, headers[2]), 
                    headers, data)

    def test(self, stream_id):
        self.streams[stream.stream_id].send('GET / HTTP/1.1\r\n\r\n')

class TorRouter(TLSClient):
    def __init__(self, node):
        self.node = node
        self.circuits = {}
        self.cell = None
        self.in_buffer = ''

        super(TorRouter, self).__init__(node['ip'], node['or_port'])

        log.info('initiating connection to guard node.')
        self.register_local('handshook', self.initial_handshake)
        self.register_local('received', self.received)
        self.register_local('got_cell_Versions', self.got_versions)
        self.register_local('got_cell_Certs', self.got_certs)
        self.register_local('got_cell_AuthChallenge', self.got_authchallenge)
        self.register_local('got_cell_Netinfo', self.got_netinfo)
        self.register_local('send_cell', self.send_cell)

        self.register('tor_init_circuit', self.init_circuit)

    def initial_handshake(self):
        log.info('connected to guard node established.')
        self.send_cell(cell.Versions())

        # version   = self.parse_cell()
        # certs     = self.parse_cell()
        # challenge = self.parse_cell()
        # netinfo   = self.parse_cell()

        # cell.Netinfo(self.sock, data={
        #     'me': netinfo.our_address,
        #     'other': netinfo.router_addresses[0]
        # })

    def received(self, data):
        self.in_buffer += data

        while self.in_buffer:
            log.debug('received data: %s' % self.in_buffer.encode('hex'))

            if not self.cell:
                if cell.proto_version < 4 and len(self.in_buffer) < 3:
                    break
                elif cell.proto_version == 4 and len(self.in_buffer) < 5:
                    break

                if cell.proto_version < 4:
                    header = struct.unpack('>HB', self.in_buffer[:3])
                    self.in_buffer = self.in_buffer[3:]
                else:
                    header = struct.unpack('>IB', self.in_buffer[:5])
                    self.in_buffer = self.in_buffer[5:]

                if header[1] in cell.cell_types:
                    self.cell = cell.cell_types[header[1]](header[0])
                else:
                    log.warning('received unknown cell type: %d.' % header[1])
                    break

                log.info('received cell header type %s' % cell.cell_type_to_name(header[1]))
            elif self.cell and self.cell.fixed:
                if len(self.in_buffer) < 509:
                    break

                self.cell.unpack(self.in_buffer[:509])
                self.in_buffer = self.in_buffer[509:]

                log.info('parsed cell type %s' %
                    cell.cell_type_to_name(self.cell.cell_type))

                self.trigger_local('got_cell_%s' %
                    cell.cell_type_to_name(self.cell.cell_type), self.cell)
                self.cell = None
            elif self.cell and not self.cell.fixed and not self.cell.has_len():
                if len(self.in_buffer) < 2:
                    break

                self.cell.len(self.in_buffer[:2])
                self.in_buffer = self.in_buffer[2:]
            elif self.cell and not self.cell.fixed:
                if len(self.in_buffer) < self.cell.len():
                    break

                self.cell.unpack(self.in_buffer[:self.cell.len()])
                self.in_buffer = self.in_buffer[self.cell.len():]

                log.info('parsed cell type %s' %
                    cell.cell_type_to_name(self.cell.cell_type))

                self.trigger_local('got_cell_%s' %
                    cell.cell_type_to_name(self.cell.cell_type), self.cell)
                self.cell = None

    def send_cell(self, c, data=None):
        if not data:
            data = ''
        log.info('sending cell type %s' % cell.cell_type_to_name(c.cell_type))
        log.debug('sending cell: ' + c.pack(data).encode('hex'))
        self.trigger_local('send', c.pack(data))

    def init_circuit(self):
        circuit = Circuit(self)
        self.circuits[circuit.circuit_id] = circuit

    def recv(self):
        cell = self.parse_cell()

        if cell.circuit_id in self.circuits:
            self.circuits[cell.circuit_id].recv_cell(cell)

    def got_versions(self, versions):
        cell.proto_version = max(versions.versions)

    def got_certs(self, certs):
        self.certs = certs
        log.debug(self.certs.certs)

    def got_authchallenge(self, authchallenge):
        self.authchallenge = authchallenge

    def got_netinfo(self, netinfo):
        self.netinfo = netinfo

        self.trigger_local('send_cell', cell.Netinfo(), {
            'me': netinfo.our_address,
            'other': netinfo.router_addresses[0]
        })

        self.trigger('tor_init_circuit')

class Router(Module):
    def module_load(self):
        self.register('tor_init_router', self.init_router)

    def init_router(self, md):
        router = TorRouter(md)
        router.init()
