from core.LocalModule import LocalModule
import modules.Tor.crypto as crypto
from modules.Tor.TorStream import TorStream
from modules.Tor.cell import cell

import socket
import struct
import random
import logging
log = logging.getLogger(__name__)

circuit = [
    {
        'name': 'SoulOfTheInternet',
        'identity': 'Bn+ciFveEejIbpXMfsRdSMIqhbM',
        'ntor-onion-key': 'ke4UGT4lz5w0qLW3iAo6lKNSWzCOtqeTgKV71D25CEE=',
        'ip': '109.239.48.152',
        'or_port': 6666
    },
    {
        'name': 'somerandomrelay',
        'identity': 'Bro6UtYfzynG8m4ZU7BQthvYT5U',
        'ntor-onion-key': 'Ya9kbcPazEARb25B37Y8YJ+iO0HjoCBQxPfztr8Bc2Y=',
        'ip': '37.139.3.231',
        'or_port': 9001
    },
    {
        'name': 'aurora',
        'identity': 'N5+0UAENFweLN2bCJzMDw1jDpEI',
        'ntor-onion-key': '52jPYtN+/mNeaQN2D1AWw1qkvLJh1RJTh6bwlaq0fFQ=',
        'ip': '176.126.252.12',
        'or_port': 8080
    }
]

class Circuit(LocalModule):
    """
    Tor circuit.
    """

    def __init__(self, proxy, circuit_id=None):
        """
        Local events registered:
            * <circuit_id>_got_cell_Created2 <circuit_id> <cell>     - Created2 cell
                                                                       received in circuit.
            * <circuit_id>_got_cell_Relay <circuit_id> <cell>        - Relay cell received
                                                                       in circuit.
            * <circuit_id>_0_got_relay_EXTENDED2 <circuit_id> <cell> - EXTENDED2 cell
                                                                       received in circuit.
            * <circuit_id>_do_ntor_handshake <node>                  - Do an ntor handshake
                                                                       with a node. Extends
                                                                       or creates the
                                                                       circuit.
            * <circuit_id>_send_relay_cell <cell>                    - send a relay cell
                                                                       upstream.
        """
        super(Circuit, self).__init__()
        self._events = proxy._events

        self.counter = 0
        self.circuit_id = circuit_id or random.randint(1<<31, 1<<32)
        self.established = False
        self.streams = {}
        self.pending_ntors = []
        self.pending_ntor = None
        self.circuit = []

        self.register_local('%d_got_cell_Created2' % self.circuit_id, self.crypt_init_ntor)
        self.register_local('%d_got_cell_Relay' % self.circuit_id, self.recv_relay_cell)
        self.register_local('%d_%d_got_relay_RELAY_EXTENDED2' % (self.circuit_id, 0),
            self.crypt_init_ntor)
        self.register_local('%d_do_ntor_handshake' % self.circuit_id, self.do_ntor)
        self.register_local('%d_send_relay_cell' % self.circuit_id, self.send_relay_cell)

        log.info('initializing circuit id %d' % self.circuit_id)
        map(self.do_ntor, circuit)

    def do_ntor(self, node):
        """
        Initializes the ntor handshake.

        Local events raised:
            * send_cell <cell> [data]                     - sends a cell.
            * <circuit_id>_send_relay_cell <relay> [data] - sends a relay cell..
        """
        if self.pending_ntor:
            log.info('adding %s to circuit %d wait list.' % (node['name'], self.circuit_id))
            self.pending_ntors.append(node)
            return
        elif self.pending_ntors and node == self.pending_ntors[0]:
            self.pending_ntors.remove(node)

        log.info('extending circuit id %d to %s.' % (self.circuit_id, node['name']))

        self.pending_ntor = crypto.ntor(node)
        handshake = self.pending_ntor.get_handshake()

        if not self.circuit:
            self.trigger_local('send_cell', cell.Create2(self.circuit_id), handshake)
        else:
            identity = crypto.b64decode(node['identity'])

            data  = struct.pack('>B', 2)
            data += struct.pack('>BB4sH', 0, 6, socket.inet_aton(node['ip']),
                node['or_port'])
            data += struct.pack('>BB20s', 2, 20, identity)
            data += struct.pack('>HH', 2, len(handshake)) + handshake

            self.trigger_local('%d_send_relay_cell' % self.circuit_id, 'RELAY_EXTEND2',
                data=data)

    def crypt_init_ntor(self, circuit_id, stream_id, c=None):
        """
        Finish the ntor handshake once we receive the Created2

        Local events triggered:
            * die - kills the tor connection.
        """

        # hack for the created2 and extended2 cells.
        if not c:
            c = stream_id

        cinfo, self.pending_ntor = self.pending_ntor, None

        if isinstance(c, cell.Relay):
            _, c.Y, c.auth = struct.unpack('>H32s32s', c.data['data'][:66])

        try:
            cinfo.complete_handshake(c.Y, c.auth)
        except crypto.NtorError as e:
            log.error('bad ntor handshake: %s' % e)
            self.trigger_local('die')
            return

        log.info('completed handshake with %s in circuit id %d.' % (cinfo.node['name'], 
            self.circuit_id))
        self.circuit.append(cinfo)

        if self.pending_ntors:
            self.do_ntor(self.pending_ntors[0])
        else:
            self.circuit_initialized()

    def init_stream(self, stream_id):
        """
        Initialize a stream.
        """
        stream = TorStream(self, stream_id)
        self.streams[stream.stream_id] = stream

    def recv_relay_cell(self, circuit_id, c):
        """
        Relay cell received. We want to decrypt it and then relay it on to the correct
        stream.

        Local events raised:
            * <circuit_id>_<stream_id>_got_relay_<relay> <circuit_id> <stream_id> <cell>
                - relay cell received on this circuit for the given stream.
            * <circuit_id>_send_relay_cell <relay_command>
                - sends a relay cell.
        """
        found = None
        data = c.data

        for OR in self.circuit:
            c.data = data = OR.decrypt.update(data)
            log.debug('OR %s decrypting cell.' % OR.node['name'])

            try:
                c.parse()
            except cell.CellError as e:
                continue

            digest = OR.recv_digest.copy()
            digest.update(c.get_str(False))
            tmp_digest = digest.copy()

            digest = digest.finalize()[:4]

            if c.data['digest'] != digest:
                continue
            else:
                found = OR
                break

        if not found:
            return

        found.recv_digest = tmp_digest

        # Every RELAY_DATA cell increments the circuit counter. Once the circuit counter
        # hits 100, we must tell the circuit we want more relay cells.
        if c.data['command_text'] == 'RELAY_DATA':
            self.counter += 1
            log.debug('circuit id %d counter: %d' % (self.circuit_id, self.counter))

            if self.counter == 100:
                log.debug('sending RELAY_SENDME to reset cell counter.')
                self.counter = 0
                self.trigger_local('%d_send_relay_cell' % self.circuit_id, 'RELAY_SENDME')

        self.trigger_local('%d_%d_got_relay_%s' % (self.circuit_id, c.data['stream_id'],
            c.data['command_text']), self.circuit_id, c.data['stream_id'], c)

    def send_relay_cell(self, command, stream_id=None, data=None, last=None):
        """
        Generate, encrypt, and send a relay cell with the given command. If the
        command is a string, it will be converted to the command id.

        Circuit local events raised:
            * send_cell <cell> [stream_id] [data] - sends a cell.
        """
        if isinstance(command, str):
            command = cell.relay_name_to_command(command)

        if command == cell.relay_name_to_command('RELAY_EXTEND2'):
            c = cell.RelayEarly(self.circuit_id)
        else:
            c = cell.Relay(self.circuit_id)

        got_dest = None
        for OR in self.circuit[::-1]:
            if not got_dest and last and OR.node['name'] != last:
                continue

            if not got_dest:
                got_dest = True

                c.init_relay({
                    'command': command,
                    'stream_id': stream_id or 0,
                    'data': data
                })

                OR.send_digest.update(c.get_str(False))
                digest = OR.send_digest.copy()
                c.data['digest'] = digest.finalize()[:4]

            c.data = OR.encrypt.update(c.get_str())

        self.trigger_local('send_cell', c)

    def circuit_initialized(self):
        """
        Called after negotiating the key exchange to initialize the circuit.

        Local events registered:
            * <circuit_id>_init_stream <stream_id> - create a new stream on this circuit
                                                     with the given stream id.

        Local events raised:
            * <circuit_id>_circuit_initialized <circuit_id>
                - indicates that the circuit is ready to use.
        """
        self.established = True
        log.info('established circuit id %d.' % self.circuit_id)
        self.register_local('%d_init_stream' % self.circuit_id, self.init_stream)
        self.trigger_local('%d_circuit_initialized' % self.circuit_id, self.circuit_id)
