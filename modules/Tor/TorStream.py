from core.LocalModule import LocalModule
import logging
log = logging.getLogger(__name__)

class TorStream(LocalModule):
    """
    A Tor stream in a circuit.
    """

    def __init__(self, circuit, stream_id=None):
        """
        Circuit local events registered:
            * <circuit_id>_<stream_id>_got_relay_RELAY_CONNECTED <circuit_id> <stream_id>
                <cell> - got a RELAY_CONNECTED cell.
            * <circuit_id>_<stream_id>_got_relay_RELAY_END <circuit_id> <stream_id> <cell>
                - got a RELAY_END cell.
            * <circuit_id>_<stream_id>_got_relay_RELAY_DATA <circuit_id> <stream_id> <cell>
                - got a RELAY_DATA cell.


        Events registered:
            * tor_stream_<stream_id>_init_directory_stream         - initialize as
                                                                     directory stream.
            * tor_stream_<stream_id>_init_tcp_stream <host> <port> - initialize a TCP
                                                                     stream.

        Events raised:
            * tor_stream_<stream id>_initialized - indicates that the stream has been
                                                   attached to a circuit and is ready to
                                                   connect.
        """
        super(TorStream, self).__init__()

        self.closed  = False
        self.connected = False
        self.circuit = circuit
        self.data    = ''
        self.stream_id = stream_id or random.randint(1, 65535)

        self.circuit.register_local('%d_%d_got_relay_RELAY_CONNECTED' % 
            (self.circuit.circuit_id, self.stream_id), self.got_relay_connected)
        self.circuit.register_local('%d_%d_got_relay_RELAY_END' % (self.circuit.circuit_id, 
            self.stream_id), self.got_relay_end)
        self.circuit.register_local('%d_%d_got_relay_RELAY_DATA' % (self.circuit.circuit_id,
            self.stream_id), self.got_relay_data)

        self.register('tor_stream_%d_init_directory_stream' % self.stream_id,
            self.directory_stream)
        self.register('tor_stream_%d_init_tcp_stream' % self.stream_id, self.tcp_stream)

        self.trigger('tor_stream_%d_initialized' % self.stream_id)

        self.counter = 0

    def got_relay_connected(self, circuit_id, stream_id, _cell):
        """
        Handles received relay cells.

        Events registered:
            * tor_stream_<stream_id>_send <data> - send data through a stream.

        Events raised:
            * tor_stream_<stream_id>_connected <stream_id> - stream connected.
        """
        log.info('stream %d: got relay connected cell' % stream_id)

        self.connected = True
        self.register('tor_stream_%s_send' % self.stream_id, self.send)
        self.trigger('tor_stream_%s_connected' % self.stream_id, self.stream_id)

    def got_relay_end(self, circuit_id, stream_id, _cell):
        """
        Handles received relay end cells.

        Events raised:
            * tor_stream_<stream_id>_closed - stream closed.
        """
        log.info('stream %d: got relay end cell' % stream_id)

        self.connected = False
        self.closed = True
        self.trigger('tor_stream_%s_closed' % self.stream_id)

    def got_relay_data(self, circuit_id, stream_id, _cell):
        """
        Handles received relay data cells.

        Circuit-local events raised:
            * <circuit_id>_send_relay_cell <relay> <stream_id> - send relay cell over
                                                                 circuit.

        Events raised:
            * tor_stream_<stream_id>_recv <data> - data received from stream.
        """
        log.debug('stream %d: got relay data cell' % stream_id)

        self.counter += 1

        if self.counter == 50:
            self.counter = 0
            self.circuit.trigger_local('%d_send_relay_cell' % self.circuit.circuit_id,
                'RELAY_SENDME', stream_id=self.stream_id)

        self.trigger('tor_stream_%s_recv' % self.stream_id, _cell.data['data'])

    def send(self, data):
        """
        Send data down a stream, breaks into PAYLOAD_LEN - 11 byte chunks.

        Circuit-local events raised:
            * <circuit_id>_send_relay_cell <relay> <stream_id> <data> - send relay cell over
                                                                        circuit.
        """
        while data:
            self.circuit.trigger_local('%d_send_relay_cell' % self.circuit.circuit_id,
                'RELAY_DATA', self.stream_id, data[:509-11])
            data = data[509-11:]

    def directory_stream(self):
        """
        Sends a RELAY_BEGIN_DIR cell.

        Circuit-local events raised:
            * <circuit_id>_send_relay_cell <relay> <stream_id> - send relay cell over
                                                                 circuit.
        """
        self.circuit.trigger_local('%d_send_relay_cell' % self.circuit.circuit_id,
            'RELAY_BEGIN_DIR', self.stream_id)

    def tcp_stream(self, host, port):
        """
        Sends a RELAY_BEGIN cell to connect to the address.

        Circuit-local events raised:
            * <circuit_id>_send_relay_cell <relay> <stream_id> <data> - send relay cell
                                                                        over circuit.
        """
        self.circuit.trigger_local('%d_send_relay_cell' % self.circuit.circuit_id,
            'RELAY_BEGIN', self.stream_id, data='%s:%d\00' + struct.pack('>I', 1))
