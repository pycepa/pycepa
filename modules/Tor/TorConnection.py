from core.TLSClient import TLSClient
from modules.Tor.cell import cell
from modules.Tor.cell import parser as cell_parser
from modules.Tor.Circuit import Circuit
import random
import ssl

import logging
log = logging.getLogger(__name__)

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
            * tor_<or_name>_init_stream <stream_id> - initiate a stream with the given
                                                      stream id.
        """
        self.node = node
        self.circuits = []
        self.cell = None
        self.in_buffer = ''
        self.name = node['name']

        super(TorConnection, self).__init__(node['ip'], node['or_port'])

        if hasattr(ssl, 'SSLContext'):
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            self.context.set_ciphers(
                'ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:'
                'DHE-DSS-AES256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:'
                'ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-AES128-SHA:'
                'ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:'
                'DHE-DSS-AES128-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-AES128-SHA:'
                'ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-AES128-SHA:RSA-RC4-MD5:RSA-RC4-SHA:'
                'RSA-AES128-SHA:ECDHE-ECDSA-DES192-SHA:ECDHE-RSA-DES192-SHA:'
                'EDH-RSA-DES192-SHA:EDH-DSS-DES192-SHA:ECDH-RSA-DES192-SHA:'
                'ECDH-ECDSA-DES192-SHA:RSA-FIPS-3DES-EDE-SHA:RSA-DES192-SHA'
            )
        else:
            self.context = ssl

        log.info('initiating connection to guard node %s: %s:%d.' % (self.node['name'], 
            self.node['ip'], self.node['or_port']))

        self.register_local('handshook', self.initial_handshake)
        self.register_local('received', self.received)
        self.register_local('send_cell', self.send_cell)
        self.register_local('0_got_cell_Versions', self.got_versions)
        self.register_local('0_got_cell_Certs', self.got_certs)
        self.register_local('0_got_cell_AuthChallenge', self.got_authchallenge)
        self.register_local('0_got_cell_Netinfo', self.got_netinfo)
        self.register('tor_%s_init_stream' % self.name, self.init_stream)

        self.init()
        self.waiting = {}

    def initial_handshake(self):
        """
        Start the initial handshake by sending a versions sell.

        Local events triggered:
            * send_cell <cell> - sends a cell down the socket.
        """
        log.info('connection to guard node established.')
        self.trigger_local('send_cell', cell.Versions())

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
        log.debug('sending cell type %s' % cell.cell_type_to_name(c.cell_type))
        log.debug('sending cell: ' + c.pack(data).encode('hex'))
        self.trigger_local('send', c.pack(data))

    def init_circuit(self):
        """
        Initialize a circuit.
        """
        circuit = Circuit(self)
        self.register_local('%d_circuit_initialized' % circuit.circuit_id,
            self.circuit_initialized)
        return circuit.circuit_id

    def circuit_initialized(self, circuit_id):
        self.circuits.append(circuit_id)

    def got_versions(self, circuit_id, versions):
        """
        Got versions cell, sets version to the highest that we share.
        """
        log.info('OR %s: got versions' % self.name)
        cell.proto_version = max(versions.versions)

    def got_certs(self, circuit_id, certs):
        """
        Got certs cell, currently does nothing.
        """
        log.info('OR %s: got certs' % self.name)
        self.certs = certs

    def got_authchallenge(self, circuit_id, authchallenge):
        """
        Got authchallenge. Currently does nothing.
        """
        log.info('OR %s: got authchallenge' % self.name)
        self.authchallenge = authchallenge

    def got_netinfo(self, circuit_id, netinfo):
        """
        Got the netinfo cell, send our own.

        Events raied:
            * tor_<or_name>_proxy_initialized <or_name> - tor connection is ready to use.

        Local events raised:
            * send_cell <cell> <data> - sends a cell down the wire.
        """
        log.info('OR %s: got netinfo' % self.name)
        self.netinfo = netinfo

        self.trigger_local('send_cell', cell.Netinfo(), {
            'me': netinfo.our_address,
            'other': netinfo.router_addresses[0]
        })

        self.trigger('tor_%s_proxy_initialized' % self.name, self.name)

    def init_stream(self, stream_id):
        """
        Finds or creates a circuit for a directory stream.

        Local events registered:
            * <circuit_id>_circuit_initialized <circuit_id>  - circuit has been initialized.
            * <circuit_id>_init_stream <stream_id>           - initialize a stream on a
                                                               circuit with the given
                                                               stream id.
        """
        if not self.circuits:
            circuit_id = self.init_circuit()
            self.waiting[circuit_id] = stream_id
            self.register_once_local('%d_circuit_initialized' % circuit_id,
                self.do_stream)
        else:
            self.trigger_local('%d_init_stream' % random.choice(self.circuits), stream_id)

    def do_stream(self, circuit_id):
        """
        Initialize a directory stream on a circuit.

        Local events raised:
            * <circuit_id>_init_stream <stream_id> - initialize a stream on a circuit with
                                                     the given stream id.
        """
        stream_id = self.waiting[circuit_id]
        del self.waiting[circuit_id]
        self.trigger_local('%d_init_stream' % circuit_id, stream_id)
