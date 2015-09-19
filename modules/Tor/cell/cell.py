from cryptography import x509
from cryptography.hazmat.backends import default_backend
from time import time
from datetime import datetime
import struct
import os
import socket
import logging
log = logging.getLogger(__name__)

# default protocol version before negotiation
proto_version = 3

class CellError(Exception):
    """
    Generic cell error.
    """
    pass

class TorError(Exception):
    """
    Generic tor protocol error.
    """
    pass

class FixedCell(object):
    """
    Fixed length cell.
    """
    cell_type = -1

    def __init__(self, circuit_id=None):
        self.fixed = True
        self.circuit_id = circuit_id or 0

    def unpack(self, data):
        self.data = data

    def pack(self, data):
        """
        Pack the circuit id, cell type, and data.
        """
        if proto_version < 4:
            data = struct.pack('>HB509s', self.circuit_id, self.cell_type, data)
        else:
            data = struct.pack('>IB509s', self.circuit_id, self.cell_type, data)
        return data

class VariableCell(object):
    """
    Variable lengthed cell.
    """
    cell_type = -1

    def __init__(self, circuit_id=None):
        self.fixed = False
        self.circuit_id = circuit_id or 0

    def has_len(self):
        """
        Returns true if the length header has been parsed.
        """
        return hasattr(self, 'length')

    def len(self, data=None):
        """
        Get or set the length of the cell.
        """
        if data:
            self.length = struct.unpack('>H', data[:2])[0]
        elif self.has_len():
            return self.length

    def unpack(self, data):
        self.data = data[:self.length]

    def pack(self, data):
        """
        Pack the circuit id, cell type, length, and data.
        """
        if proto_version < 4:
            header = struct.pack('>HBH', self.circuit_id, self.cell_type, len(data))
        else:
            header = struct.pack('>IBH', self.circuit_id, self.cell_type, len(data))
        return header + data

class Relay(FixedCell):
    """
    Relay cell.
    """
    cell_type = 3

    def get_str(self, include_digest=True):
        """
        Returns the packed data without sending so that it can be encrypted.
        """
        if isinstance(self.data, str):
            return self.data

        if not self.data['data']:
            self.data['data'] = ''

        if include_digest:
            digest = self.data['digest']
        else:
            digest = '\x00' * 4

        return struct.pack('>BHH4sH498s', self.data['command'], 0,
            self.data['stream_id'], digest, len(self.data['data']), self.data['data'])

    def parse(self):
        """
        Parse a received relay cell after decryption. This currently can't be implemented
        as a part of the unpack() function because the data must first be decrypted.
        """
        headers = struct.unpack('>BHH4sH', self.data[:11])
        self.data = self.data[11:]

        if len(self.data) < headers[4] or headers[1]:
            raise CellError('Invalid relay packet (possibly not from this OR).')

        try:
            text = relay_commands[headers[0]]
        except IndexError:
            raise CellError('Invalid relay packet command.')

        self.data = {
            'command': headers[0],
            'command_text': text,
            'recognized': headers[1],
            'stream_id': headers[2],
            'digest': headers[3],
            'length': headers[4],
            'data': self.data[:headers[4]]
        }

    def pack(self, data):
        return super(Relay, self).pack(self.data)

    def init_relay(self, data):
        """
        Set the relay cell data.
        """
        self.data = data

class Padding(FixedCell):
    """
    Padding cell.
    """
    cell_type = 0

class Destroy(FixedCell):
    """
    Destroy cell.
    """
    cell_type = 4

    def unpack(self, data):
        super(Destroy, self).unpack(data)

        reason = struct.unpack('>B', self.data[0])[0]
        reasons = [
            'No reason given.', 'Tor protocol violation.', 'Internal error.',
            'A client sent a TRUNCATE command.',
            'Not currently operating; trying to save bandwidth.',
            'Out of memory, sockets, or circuit IDs.',
            'Unable to reach relay.',
            'Connected to relay, but its OR identity was not as expected.',
            'The OR connection that was carrying this circuit died.',
            'The circuit has expired for being dirty or old.'
            'Circuit construction took too long.',
            'The circuit was destroyed w/o client TRUNCATE.',
            'Request for unknown hidden service.'
        ]

        raise TorError('Circuit closed: %s' % reasons[reason])

class CreateFast(FixedCell):
    """
    CreateFast cell.
    """
    cell_type = 5

    def __init__(self, circuit_id=None):
        super(CreateFast, self).__init__(circuit_id=circuit_id)
        self.key_material = os.urandom(20)

    def pack(self, data):
        data = struct.pack('>20s', self.key_material)
        return super(CreateFast, self).pack(data)

class CreatedFast(FixedCell):
    """
    CreatedFast cell.
    """
    cell_type = 6

    def unpack(self, data):
        """
        Unpack the key material.
        """
        super(CreatedFast, self).unpack(data)
        self.key_material, self.derivative_key = struct.unpack('>20s20s', self.data[:40])

class Versions(VariableCell):
    """
    Versions cell.
    """
    cell_type = 7

    def unpack(self, data):
        """
        Parse the received versions.
        """
        super(Versions, self).unpack(data)
        self.versions = struct.unpack('>' + 'H' * int(len(self.data) / 2), self.data)

    def pack(self, data):
        """
        Pack our known versions.
        """
        data = struct.pack('>HH', 3,4)
        return super(Versions, self).pack(data)

class Netinfo(FixedCell):
    """
    Netinfo cell.
    """
    cell_type = 8

    def unpack(self, data):
        """
        Parse out netinfo.
        """
        super(Netinfo, self).unpack(data)

        data = self.data
        time = struct.unpack('>I', data[:4])[0]
        data = data[4:]

        # decode our IP address
        host_type, address, data = self.decode_ip(data)
        self.our_address = address

        self.router_addresses = []

        # iterate over OR addresses.
        num_addresses = data[0]
        if not isinstance(num_addresses, int):
            num_addresses = struct.unpack('B', num_addresses)[0]

        data = data[1:]
        for _ in range(num_addresses):
            host_type, address, data = self.decode_ip(data)
            self.router_addresses.append(address)

    def decode_ip(self, data):
        """
        Decode IPv4 and IPv6 addresses.
        """
        host_type, size = struct.unpack('>BB', data[:2])
        data = data[2:]

        address = struct.unpack('>%ds' % size, data[:size])[0]
        data    = data[size:]

        if host_type == 4:
            address = socket.inet_ntop(socket.AF_INET, address)
        elif host_type == 6:
            address = socket.inet_ntop(socket.AF_INET6, address)
        else:
            raise CellError('Do we allow hostnames in NETINFO?')

        return host_type, address, data

    def pack(self, data):
        """
        Pack our own netinfo.
        """
        ips = data

        data  = struct.pack('>I', int(time()))
        data += self.encode_ip(ips['other'])
        data += struct.pack('>B', 1)
        data += self.encode_ip(ips['me'])

        return super(Netinfo, self).pack(data)

    def encode_ip(self, ip):
        """
        Encode an IPv4 address.
        """
        return struct.pack('>BB', 4, 4) + socket.inet_aton(ip)

class RelayEarly(Relay):
    """
    RelayEarly cell.
    """
    cell_type = 9

class Create2(FixedCell):
    """
    Create2 cell.
    """
    cell_type = 10

    def pack(self, data):
        data = struct.pack('>HH', 0x2, len(data)) + data
        return super(Create2, self).pack(data)

class Created2(FixedCell):
    """
    Created2 cell.
    """
    cell_type = 11

    def unpack(self, data):
        super(Created2, self).unpack(data)
        length, self.Y, self.auth = struct.unpack('>H32s32s', data[:66])

class Certs(VariableCell):
    """
    Certs cell.
    """
    cell_type = 129

    def unpack(self, data):
        """
        Unpack a certs cell. Parses out all of the send certs and does *very* basic
        validation.
        """
        super(Certs, self).unpack(data)

        data      = self.data

        num_certs = data[0]
        if not isinstance(num_certs, int):
            num_certs = struct.unpack('>B', num_certs)[0]

        data = data[1:]

        now = datetime.now().strftime('%Y%m%d%H%M%S%z')

        self.certs = {}
        for _ in range(num_certs):
            # get cert type and length
            cert_info = struct.unpack('>BH', data[:3])
            data = data[3:]

            # unpack the cert
            cert_type = cert_info[0]
            cert = struct.unpack('>%ds' % cert_info[1], data[:cert_info[1]])[0]
            data = data[cert_info[1]:]

            # we only want one of each certificate type
            if cert_type in self.certs or int(cert_type) > 3:
                raise CellError('Duplicate or invalid certificate received.')

            # load the certificate and check expiration.
            # cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
            cert = x509.load_der_x509_certificate(cert, default_backend())
            now = datetime.now()
            if cert.not_valid_before > now or cert.not_valid_after < now:
                log.error('got invalid certificate date.')
                raise CellError('Certificate expired.')

            self.certs[cert_type] = cert
            log.info('got cert type %d, hash: %s' % (cert_type, cert))

class AuthChallenge(VariableCell):
    """
    AuthChallenge cell.
    """
    cell_type = 130

    def unpack(self, data):
        """
        Unpack the auth challenge. Currently not doing anything with it.
        """
        super(AuthChallenge, self).unpack(data)

        struct.unpack('>32sH', self.data[:34])

def cell_type_to_name(cell_type):
    """
    Convert a cell type to its name.
    """
    if cell_type in cell_types:
        return cell_types[cell_type].__name__
    else:
        return ''

def relay_name_to_command(name):
    """
    Converts relay name to a command.
    """
    if name in relay_commands:
        return relay_commands.index(name)
    else:
        return -1

# List of cell types.
cell_types = {
    0: Padding,
    3: Relay,
    4: Destroy,
    5: CreateFast,
    6: CreatedFast,
    7: Versions,
    8: Netinfo,
    9: RelayEarly,
    10: Create2,
    11: Created2,
    129: Certs,
    130: AuthChallenge
}

# List of relay commnads.
relay_commands = [
    '', 'RELAY_BEGIN', 'RELAY_DATA', 'RELAY_END', 'RELAY_CONNECTED', 'RELAY_SENDME',
    'RELAY_EXTEND', 'RELAY_EXTENDED', 'RELAY_TRUNCATE', 'RELAY_TRUNCATED', 
    'RELAY_DROP', 'RELAY_RESOLVE', 'RELAY_RESOLVED', 'RELAY_BEGIN_DIR',
    'RELAY_EXTEND2', 'RELAY_EXTENDED2'
]
