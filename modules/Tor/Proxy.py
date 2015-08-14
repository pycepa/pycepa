from core.TLSClient import TLSClient
from core.Module import Module
from core.LocalModule import LocalModule
from Crypto.Cipher import AES
from modules.Tor.DirServ import authorities
from modules.Tor.cell import cell
from modules.Tor.cell import parser as cell_parser
from hashlib import sha1
import random
import struct
import logging
log = logging.getLogger(__name__)

class TorStream(LocalModule):
    """
    A Tor stream in a circuit.
    """

    def __init__(self, circuit, stream_id=None):
        """
        Circuit local events registered:
            * <circuit_id>_<stream_id>_got_relay <circuit_id> <stream_id> <cell>
                - got a relay cell.
            * <circuit_id>_<stream_id>_init_directory_stream <circuit_id> <stream_id>
                - initialize the directory stream.
        """
        super(TorStream, self).__init__()

        self.closed  = False
        self.connected = False
        self.circuit = circuit
        self.data    = ''
        self.stream_id = stream_id or random.randint(1, 65535)

        self.circuit.register_local('%d_%d_got_relay' % (self.circuit.circuit_id, 
            self.stream_id), self.got_relay)
        self.circuit.register_local('%d_%d_init_directory_stream' % 
            (self.circuit.circuit_id, self.stream_id), self.directory_stream)

    def gen_cell(self, command, data=None, digest=None):
        """
        Generate a relay cell with the given command. If the command is a string, it will
        be converted to the command id.
        """
        c = cell.Relay(self.circuit.circuit_id)

        if isinstance(command, str):
            command = cell.relay_name_to_command(command)

        c.init_relay({
            'command': command,
            'stream_id': self.stream_id,
            'digest': digest or '\x00' * 4,
            'data': data
        })
        return c

    def send_cell(self, c):
        """
        Encrypts and sends a relay cell.

        Circuit local events raised:
            * send_cell <cell> - sends a cell.
        """
        self.circuit.send_digest.update(c.get_str())
        c.data['digest'] = self.circuit.send_digest.digest()[:4]
        c.data = self.circuit.encrypt(c.get_str())
        self.circuit.trigger_local('send_cell', c)

    def connect(self, addr, port):
        """
        Iniatializes a remote TCP connection.
        """
        data = '%s:%d\0%s' % (addr, port, struct.pack('>I', 0))
        self.send_cell(self.gen_cell('RELAY_BEGIN', data))

    def got_relay(self, circuit_id, stream_id, _cell):
        """
        Handles received relay cells.

        Events registered:
            * tor_directory_stream_<stream_id>_send <data> - send data through a stream.

        Events raised:
            * tor_directory_stream_<stream_id>_connected <stream_id> - stream connected.
            * tor_directory_stream_<stream_id>_closed                - stream closed.
            * tor_directory_stream_<stream_id>_recv <data>           - data received from
                                                                       stream.
        """
        command = _cell.data['command_text']
        log.debug('Got relay cell: %s' % command)

        if command == 'RELAY_CONNECTED':
            self.connected = True
            self.register('tor_directory_stream_%s_send' % self.stream_id, self.send)
            self.trigger('tor_directory_stream_%s_connected' % self.stream_id,
                self.stream_id)
        elif command == 'RELAY_END':
            self.connected = False
            self.closed = True
            self.trigger('tor_directory_stream_%s_closed' % self.stream_id)
        elif command == 'RELAY_DATA':
            self.trigger('tor_directory_stream_%s_recv' % self.stream_id,
                _cell.data['data'])

    def send(self, data):
        self.send_cell(self.gen_cell('RELAY_DATA', data))

    def directory_stream(self, circuit_id, stream_id):
        self.send_cell(self.gen_cell('RELAY_BEGIN_DIR'))

class Circuit(LocalModule):
    """
    Tor circuit.
    """

    def __init__(self, proxy, circuit_id=None):
        """
        Local events registered:
            * <circuit_id>_got_cell_CreatedFast <circuit_id> <cell> - CreatedFast cell
                                                                      received in circuit.
            * <circuit_id>_got_cell_Relay <circuit_id> <cell>       - Relay cell received
                                                                      in circuit.
        """
        super(Circuit, self).__init__()
        self._events = proxy._events

        self.circuit_id = circuit_id or random.randint(1<<31, 1<<32)

        self.established = False
        self.streams     = {}

        self.register_local('%d_got_cell_CreatedFast' % self.circuit_id, self.recv_cell)
        self.register_local('%d_got_cell_Relay' % self.circuit_id, self.recv_cell)

        log.info('initializing circuit id %d' % self.circuit_id)
        # Create our CreateFast cell. Initializes the key material that we will be using.
        c = cell.CreateFast(circuit_id=self.circuit_id)
        self.Y = c.key_material

        self.trigger_local('send_cell', c)

    def crypt_init(self):
        """
        Initializes the AES encryption / decryption using the TAP handshake (tor-spec.txt,
        section 5.1.3).
        """
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

    def connect(self, stream_id):
        """
        Initialize a stream on the circuit.
        """
        stream = TorStream(self, stream_id)
        self.streams[stream.stream_id] = stream

    def init_directory_stream(self, stream_id):
        """
        Initiate a directory stream.

        Local events raised:
            * <circuit_id>_<stream_id>_init_directory_stream <circuit_id> <stream_id> -
                initiate a directory stream.
            * <circuit_id>_<stream_id>_stream_initialized <circuit_id> <stream_id> -
                stream initialized (but not connected).
        """
        self.connect(stream_id)
        self.trigger_local('%d_%d_init_directory_stream' % (self.circuit_id,
            stream_id), self.circuit_id, stream_id)
        self.trigger_local('%d_%d_stream_initialized' % (self.circuit_id,
            stream_id), self.circuit_id, stream_id)

    def recv_cell(self, circuit_id, c):
        """
        Cell received. If it's a CreatedFast this is a fresh circuit that is ready to use.
        If it's a relay cell, then it gets forwarded to the appropriate stream.
        
        Local events registered:
            * <circuit_id>_init_directory_stream <stream_id> - create a new directory stream
                                                               on this circuit with the 
                                                               given stream id.

        Local events raised:
            * <circuit_id>_circuit_initialized <circuit_id> 
                - indicates that the circuit is ready to use.
            * <circuit_id>_<stream_id>_got_relay <circuit_id> <stream_id> <cell>
                - cell received on this circuit for the given stream.
        """
        if isinstance(c, cell.CreatedFast):
            self.X = c.key_material
            self.crypt_init()
            self.established = True
            log.info('established circuit id %d.' % self.circuit_id)
            self.register_local('%d_init_directory_stream' % self.circuit_id, 
                self.init_directory_stream)
            self.trigger_local('%d_circuit_initialized' % self.circuit_id, self.circuit_id)
        elif isinstance(c, cell.Relay):
            c.data = self.decrypt(c.data)
            c.parse()

            if c.data['stream_id'] in self.streams:
                self.trigger_local('%d_%d_got_relay' % (self.circuit_id,
                    c.data['stream_id']), self.circuit_id, c.data['stream_id'], c)

class TorConnection(TLSClient):
    """
    Connection to a Tor router.
    """
    def __init__(self, node):
        """
        Local events registered:
            * handshook                                       - TLS handshake completed.
            * received <data>                                 - data received from socket.
            * send_cell <cell> [data]                         - send a cell.
            * 0_got_cell_Versions <circuit_id> <cell>         - got the version cell.
            * 0_got_cell_Certs <circuit_id> <cell>            - got the certs cell.
            * 0_got_cell_AuthChallenge <circuit_id> <cell>    - got the authchallenge cell.
            * 0_got_cell_Netinfo <circuit_id> <cell>          - got the netinfo cell.

        Events registered:
            * tor_<or_name>_init_directory_stream <stream_id> - initiate a directory stream
                                                                with the given stream id.
        """
        self.node = node
        self.circuits = {}
        self.cell = None
        self.in_buffer = ''
        self.name = node['name']

        super(TorConnection, self).__init__(node['ip'], node['or_port'])

        log.info('initiating connection to guard node.')
        self.register_local('handshook', self.initial_handshake)
        self.register_local('received', self.received)
        self.register_local('send_cell', self.send_cell)
        self.register_local('0_got_cell_Versions', self.got_versions)
        self.register_local('0_got_cell_Certs', self.got_certs)
        self.register_local('0_got_cell_AuthChallenge', self.got_authchallenge)
        self.register_local('0_got_cell_Netinfo', self.got_netinfo)
        self.register('tor_%s_init_directory_stream' % self.name,
            self.init_directory_stream)

        self.init()
        self.waiting = {}

    def initial_handshake(self):
        """
        Start the initial handshake by sending a versions sell.
        """
        log.info('connected to guard node established.')
        self.send_cell(cell.Versions())

    def received(self, data):
        """
        Received some data, parse it out and handle accordingly.

        Local events raised:
            * <circuit_id>_got_cell_<cell_type> <circuit_id> <cell> - got a cell of the
                                                                      given type.
        """
        self.in_buffer += data

        while self.in_buffer:
            try:
                log.debug('received data: %s' % self.in_buffer.encode('hex'))
                self.in_buffer, self.cell, ready, cont = cell_parser.parse_cell(
                    self.in_buffer, self.cell)
            except cell.CellError as e:
                log.error('invalid cell received: %s' % e)
                self.die()
                break

            if ready:
                self.trigger_local('%d_got_cell_%s' %
                    (self.cell.circuit_id, cell.cell_type_to_name(self.cell.cell_type)),
                    self.cell.circuit_id, self.cell)
                self.cell = None

            if not cont:
                log.debug("don't have enough bytes to read the entire cell, waiting.")
                break

    def send_cell(self, c, data=None):
        """
        Send a cell down the wire.
        
        Local events raised:
            * send <data> - sends data on the socket.
        """
        if not data:
            data = ''
        log.info('sending cell type %s' % cell.cell_type_to_name(c.cell_type))
        log.debug('sending cell: ' + c.pack(data).encode('hex'))
        self.trigger_local('send', c.pack(data))

    def init_circuit(self):
        """
        Initialize a circuit.
        """
        circuit = Circuit(self)
        self.circuits[circuit.circuit_id] = circuit
        return circuit.circuit_id

    def got_versions(self, circuit_id, versions):
        """
        Got versions cell, sets version to the highest that we share.
        """
        cell.proto_version = max(versions.versions)

    def got_certs(self, circuit_id, certs):
        """
        Got certs cell, currently does nothing.
        """
        self.certs = certs
        log.debug(self.certs.certs)

    def got_authchallenge(self, circuit_id, authchallenge):
        """
        Got authchallenge. Currently does nothing.
        """
        self.authchallenge = authchallenge

    def got_netinfo(self, circuit_id, netinfo):
        """
        Got the netinfo cell, send our own.

        Events raied:
            * tor_<or_name>_proxy_initialized <or_name> - tor connection is ready to use.

        Local events raised:
            * send_cell <cell> <data> - sends a cell down the wire.
        """
        self.netinfo = netinfo

        self.trigger_local('send_cell', cell.Netinfo(), {
            'me': netinfo.our_address,
            'other': netinfo.router_addresses[0]
        })

        self.trigger('tor_%s_proxy_initialized' % self.name, self.name)

    def init_directory_stream(self, stream):
        """
        Finds or creates a circuit for a directory stream.

        Local events registered:
            * <circuit_id>_circuit_initialized <circuit_id> - circuit has been initialized.
        """
        if not self.circuits:
            circuit_id = self.init_circuit()
            self.waiting[circuit_id] = stream
            self.register_once_local('%d_circuit_initialized' % circuit_id,
                self.do_directory_stream)

    def do_directory_stream(self, circuit_id):
        """
        Initialize a directory stream on a circuit.

        Local events raised:
            * <circuit_id>_init_directory_stream <stream_id> - initialize a directory
                                                               stream on a circuit with the
                                                               given stream id.
        """
        stream_id = self.waiting[circuit_id]
        del self.waiting[circuit_id]

        self.trigger_local('%d_init_directory_stream' % circuit_id, stream_id)

class Proxy(Module):
    """
    Tor proxy handler. Handles creation of tor connections.
    """
    def module_load(self):
        """
        Events registered:
            * tor_init_directory_stream <stream_id> - create a directory stream
        """
        self.register('tor_init_directory_stream', self.init_directory_stream)
        self.connections = []
        self.streams = []

    def init_directory_stream(self, stream_id):
        """
        Initialize a directory stream. Creates a new tor connection, if necessary.

        Events registered:
            * tor_<or_name>_proxy_initialized <or_name> - indicates that the OR connection
                                                          is ready for use.
        """
        self.streams.append(stream_id)

        if not self.connections:
            self.connections.append(TorConnection(authorities[0]))
            self.register('tor_%s_proxy_initialized' % authorities[0]['name'],
                self.proxy_initialized)

    def proxy_initialized(self, name):
        """
        Proxy is initialized, so we begin creating a stream.

        Events raised:
            * tor_<or_name>_init_directory_stream <stream_id> - initialize a directory
                                                                stream, will create
                                                                circuits as necessary.
        """
        for stream in self.streams:
            self.trigger('tor_%s_init_directory_stream' % authorities[0]['name'],
                stream)
