from OpenSSL import crypto
from time import time
from datetime import datetime
import struct
import os
import socket
import logging
log = logging.getLogger(__name__)

proto_version = 3

class CellError(Exception):
    pass

class FixedCell(object):
    cell_type = -1

    def __init__(self, circuit_id=None):
        self.fixed = True
        self.circuit_id = circuit_id or 0

    def unpack(self, data):
        self.data = data

    def pack(self, data):
        if proto_version < 4:
            data = struct.pack('>HB509s', self.circuit_id, self.cell_type, data)
        else:
            data = struct.pack('>IB509s', self.circuit_id, self.cell_type, data)
        return data

class VariableCell(object):
    cell_type = -1

    def __init__(self, circuit_id=None):
        self.fixed = False
        self.circuit_id = circuit_id or 0

    def has_len(self):
        return hasattr(self, 'length')

    def len(self, data=None):
        if data:
            self.length = struct.unpack('>H', data[:2])[0]
        elif self.has_len():
            return self.length

    def unpack(self, data):
        self.data = data[:self.length]

    def pack(self, data):
        if proto_version < 4:
            header = struct.pack('>HBH', self.circuit_id, self.cell_type, len(data))
        else:
            header = struct.pack('>IBH', self.circuit_id, self.cell_type, len(data))
        return header + data

class Relay(FixedCell):
    cell_type = 3
    relay_type = 0

    def get_str(self):
        if not self.data['data']:
            self.data['data'] = ''

        return struct.pack('>BHH4sH498s', self.relay_type, 0,
            self.data['stream_id'], self.data['digest'], len(self.data['data']),
            self.data['data'])

    # i can't (currently) implement this as the unpack() function because it needs
    # to be decrypted first.
    def parse(self):
        headers = struct.unpack('>BHHIH', self.data[:11])
        self.data = self.data[11:]

        if len(self.data) < headers[4]:
            raise CellError('Could not parse relay length.')

        self.data = {
            'command': headers[0],
            'command_text': relay_types[headers[0]],
            'recognized': headers[1],
            'stream_id': headers[2],
            'digest': headers[3],
            'length': headers[4],
            'data': self.data[:headers[4]]
        }

    def pack(self, data):
        return super(Relay, self).pack(self.data)

    def init_relay(self, data):
        self.data = data

class Padding(FixedCell):
    cell_type = 0

class Destroy(FixedCell):
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

        class TorError(Exception):
            pass

        raise TorError('Circuit closed: %s' % reasons[reason])

class CreateFast(FixedCell):
    cell_type = 5

    def __init__(self, circuit_id=None):
        super(CreateFast, self).__init__(circuit_id=circuit_id)
        self.key_material = os.urandom(20)

    def pack(self, data):
        data = struct.pack('>20s', self.key_material)
        return super(CreateFast, self).pack(data)

class CreatedFast(FixedCell):
    cell_type = 6

    def unpack(self, data):
        super(CreatedFast, self).unpack(data)
        keys = struct.unpack('>20s20s', self.data[:40])

        self.key_material   = keys[0]
        self.derivative_key = keys[1]

class Versions(VariableCell):
    cell_type = 7

    def unpack(self, data):
        super(Versions, self).unpack(data)
        self.versions = struct.unpack('>' + 'H' * (len(self.data) / 2), self.data)

    def pack(self, data):
        data = struct.pack('>HH', 3,4)
        return super(Versions, self).pack(data)

class Netinfo(FixedCell):
    cell_type = 8

    def unpack(self, data):
        super(Netinfo, self).unpack(data)

        data = self.data
        time = struct.unpack('>I', data[:4])[0]
        data = data[4:]

        host_type, address, data = self.decode_ip(data)
        self.our_address = address

        self.router_addresses = []

        num_addresses = struct.unpack('B', data[0])[0]
        data = data[1:]
        for _ in range(num_addresses):
            host_type, address, data = self.decode_ip(data)
            self.router_addresses.append(address)

    def decode_ip(self, data):
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
        ips = data

        data  = struct.pack('>I', int(time()))
        data += self.encode_ip(ips['other'])
        data += struct.pack('>B', 1)
        data += self.encode_ip(ips['me'])

        return super(Netinfo, self).pack(data)

    def encode_ip(self, ip):
        return struct.pack('>BB', 4, 4) + socket.inet_aton(ip)

class Create2(FixedCell):
    cell_type = 10

    def pack(self, data):
        htype = 0x2
        return super(Create2, self).pack(data)

class Created2(FixedCell):
    cell_type = 11

class Certs(VariableCell):
    cell_type = 129

    def unpack(self, data):
        super(Certs, self).unpack(data)

        data      = self.data
        num_certs = struct.unpack('>B', data[0])[0]
        data      = data[1:]

        now = datetime.now().strftime('%Y%m%d%H%M%S%z')

        self.certs = {}
        for _ in range(num_certs):
            cert_info = struct.unpack('>BH', data[:3])
            data = data[3:]

            cert_type = cert_info[0]
            cert = struct.unpack('>%ds' % cert_info[1], data[:cert_info[1]])[0]
            data = data[cert_info[1]:]

            if cert_type in self.certs or int(cert_type) > 3:
                raise CellError('Duplicate or invalid certificate received.')

            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
            if cert.has_expired():
                log.error('got invalid certificate date.')
                raise CellError('Certificate expired.')

            self.certs[cert_type] = cert
            log.info('got cert type %d, hash: %s' % (cert_type, cert))

class AuthChallenge(VariableCell):
    cell_type = 130

    def unpack(self, data):
        super(AuthChallenge, self).unpack(data)

        struct.unpack('>32sH', self.data[:34])

def cell_type_to_name(cell_type):
    if cell_type in cell_types:
        return cell_types[cell_type].__name__
    else:
        return ''

def relay_name_to_command(name):
    if name in relay_commands:
        return relay_commands.index(name)
    else:
        return -1

cell_types = {
    0: Padding,
    3: Relay,
    4: Destroy,
    5: CreateFast,
    6: CreatedFast,
    7: Versions,
    8: Netinfo,
    129: Certs,
    130: AuthChallenge
}

relay_commands = [
    'RELAY_BEGIN', 'RELAY_DATA', 'RELAY_END', 'RELAY_CONNECTED', 'RELAY_SENDME',
    'RELAY_EXTEND', 'RELAY_EXTENDED', 'RELAY_TRUNCATE', 'RELAY_TRUNCATED', 
    'RELAY_DROP', 'RELAY_RESOLVE', 'RELAY_RESOLVED', 'RELAY_BEGIN_DIR',
    'RELAY_EXTEND2', 'RELAY_EXTENDED2'
]
