# legacy code from the first iteration.
from .router import TorRouter
from hashlib import sha1
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from time import time
import base64
import struct

class Onion:
    def __init__(self, onion, dir_serv=None, cookie=None):
        self.import_onion(onion)
        self.cookie   = cookie
        self.dir_serv = dir_serv

    def get_hs_dirs(self):
        d_ids   = self.descriptor_ids()
        hsdirs  = {}
        found   = False

        for d_id in d_ids:
            hsdirs[d_id] = []

        for md in self.dir_serv.parse_mds():
            if 'HSDir' in md['flags']:
                tmp_d_id = (md['descriptor_id'] + '=').decode('base64')

                for d_id in d_ids:
                    if tmp_d_id > d_id and len(hsdirs[d_id]) < 3:
                        hsdirs[d_id].append(md)

                        found = True
                        for item in hsdirs:
                            if len(hsdirs[item]) != 3:
                                found = False

            if found:
                break

        return hsdirs

    def descriptor_ids(self):
        descriptor_ids = []

        for replica in range(2):
            time_period = (int(time()) + ord(self.onion[0]) * 86400 / 256) / 86400

            sha = sha1()
            sha.update(struct.pack('>I', time_period))
            if self.cookie:
                sha.update(self.cookie)
            sha.update(chr(replica))

            descriptor_id = sha1()
            descriptor_id.update(self.onion)
            descriptor_id.update(sha.digest())
            descriptor_ids.append(descriptor_id.digest())

        return descriptor_ids

    def get_public_key(self):
        public_key = False

        for descriptor_id, hsdirs in self.get_hs_dirs().iteritems():
            descriptor_id = self.b32e(descriptor_id)

            for hsdir in hsdirs:
                router  = TorRouter(hsdir)
                circuit = router.create()

                while not circuit.established:
                    router.recv()

                stream  = circuit.connect()
                stream.connect()

                request  = "GET /tor/rendezvous2/%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n"
                request %= (descriptor_id, hsdir['ip'], hsdir['dir_port'])
                stream.send(request)

                while not stream.closed:
                    router.recv()

                if stream.data.startswith('HTTP/1.0 200 OK'):
                    public_key = stream.data
                    break

            if public_key:
                break

        return public_key

    def fetch_public_key(self, dir_serv=None):
        if hasattr(self, 'key'):
            return

        if dir_serv:
            self.dir_serv = dir_serv

        public_key_data = self.get_public_key()

        """
        in_key     = False
        public_key = ''
        for line in public_key_data.split('\n'):
            if line == '-----BEGIN RSA PUBLIC KEY-----':
                in_key = True

            if in_key:
                public_key += line + '\n'

            if line == '-----END RSA PUBLIC KEY-----':
                break
        """

        pub_key = self.decode_block(public_key_data, 'RSA PUBLIC KEY')
        self.derive_onion(pub_key)

    def derive_onion(self, key):
        key = RSA.importKey(key)
        if key.has_private():
            self.private_key = key
            key = key.publickey()

        self.key   = key
        self.onion = sha1(self.export_key('DER')).digest()[:10]

    def import_onion(self, path):
        if isinstance(path, file):
            self.derive_onion(path)
            return

        onion = path.split('.')[0]

        if len(onion) == 16:
            try:
                self.onion = self.b32d(onion)
            except TypeError:
                pass
        else:
            self.derive_onion(open(path))

    def export_key(self, format='PEM'):
        key = self.key.exportKey('DER', pkcs = 1)
        key = key[:2] + key[24:]

        if format == 'PEM':
            return self.encode_block(key, 'RSA PUBLIC KEY')
        elif format == 'DER':
            return key

    def encode_block(self, block, type):
        block = base64.b64encode(block)
        out   = '-----BEGIN %s-----\n' % type
        out  += '\n'.join(block[pos:pos+64] for pos in xrange(0, len(block), 64))
        out  += '\n-----END %s-----' % type
        return out

    def decode_block(self, block, type):
        in_block, final_block = False, ''
        for line in block.split('\n'):
            if line == '-----BEGIN %s-----' % type:
                in_block = True
            elif line == '-----END %s-----' % type:
                break
            elif in_block:
                final_block += line

        return base64.b64decode(final_block)

    def b32d(self, encoded):
        return base64.b32decode(encoded, 1)

    def b32e(self, decoded):
        return base64.b32encode(decoded).lower()

    def sign(self, message):
        if not hasattr(self, 'private_key'):
            return False

        sha    = SHA.new(message)
        signer = PKCS1_v1_5.new(self.private_key)
        return self.encode_block(signer.sign(sha), 'HS SIGNATURE')

    def verify(self, message, signature):
        if not hasattr(self, 'key'):
            return False

        sha      = SHA.new(message)
        verifier = PKCS1_v1_5.new(self.key)

        return verifier.verify(sha, self.decode_block(signature, 'HS SIGNATURE'))

    def __repr__(self):
        if hasattr(self, 'onion'):
            return self.b32e(self.onion) + '.onion'
        else:
            return ''
