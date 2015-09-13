from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256, SHA1, Hash
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends import default_backend
import curve25519

import struct
import base64

bend = default_backend()

def b64decode(data):
    return base64.b64decode(data + '=' * (len(data) % 4))

def sha1(msg):
    sha = Hash(SHA1(), backend=bend)
    sha.update(msg)
    return sha.finalize()

def hmac(key, msg):
    hmac = HMAC(key, algorithm=SHA256(), backend=bend)
    hmac.update(msg)
    return hmac.finalize()

def hkdf(key, length=16, info=''):
    hkdf = HKDFExpand(algorithm=SHA256(), length=length, info=info, backend=bend)
    return hkdf.derive(key)

def hash_func(shared):
    return shared

class NtorError(Exception):
    pass

class ntor(object):
    def __init__(self, node):
        # 5.1.4. The "ntor" handshake

        # This handshake uses a set of DH handshakes to compute a set of
        # shared keys which the client knows are shared only with a particular
        # server, and the server knows are shared with whomever sent the
        # original handshake (or with nobody at all).  Here we use the
        # "curve25519" group and representation as specified in "Curve25519:
        # new Diffie-Hellman speed records" by D. J. Bernstein.

        # [The ntor handshake was added in Tor 0.2.4.8-alpha.]

        self.node = node

        # In this section, define:
        #   H(x,t) as HMAC_SHA256 with message x and key t.
        #   H_LENGTH  = 32.
        #   ID_LENGTH = 20.
        #   G_LENGTH  = 32
        #   PROTOID   = "ntor-curve25519-sha256-1"
        #   t_mac     = PROTOID | ":mac"
        #   t_key     = PROTOID | ":key_extract"
        #   t_verify  = PROTOID | ":verify"
        #   MULT(a,b) = the multiplication of the curve25519 point 'a' by the
        #               scalar 'b'.
        #   G         = The preferred base point for curve25519 ([9])
        #   KEYGEN()  = The curve25519 key generation algorithm, returning
        #               a private/public keypair.
        #   m_expand  = PROTOID | ":key_expand"

        # H is defined as hmac()
        # MULT is included in the curve25519 library as get_shared_key()
        # KEYGEN() is curve25519.Private()
        self.protoid = 'ntor-curve25519-sha256-1'
        self.t_mac = self.protoid + ':mac'
        self.t_key = self.protoid + ':key_extract'
        self.t_verify = self.protoid + ':verify'
        self.m_expand = self.protoid + ':key_expand'

        # To perform the handshake, the client needs to know an identity key
        # digest for the server, and an ntor onion key (a curve25519 public
        # key) for that server. Call the ntor onion key "B".  The client
        # generates a temporary keypair:
        #     x,X = KEYGEN()
        self.x = curve25519.Private()
        self.X = self.x.get_public()

        self.B = curve25519.Public(b64decode(self.node['ntor-onion-key']))

        # and generates a client-side handshake with contents:
        #   NODEID      Server identity digest  [ID_LENGTH bytes]
        #   KEYID       KEYID(B)                [H_LENGTH bytes]
        #   CLIENT_PK   X                       [G_LENGTH bytes]
        self.handshake  = b64decode(self.node['identity'])
        self.handshake += self.B.serialize()
        self.handshake += self.X.serialize()

    def complete_handshake(self, Y, auth):
        # The server's handshake reply is:
        # SERVER_PK   Y                       [G_LENGTH bytes]
        # AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]

        # The client then checks Y is in G^* [see NOTE below], and computes

        # secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
        si  = self.x.get_shared_key(curve25519.Public(Y), hash_func)
        si += self.x.get_shared_key(self.B, hash_func)
        si += b64decode(self.node['identity'])
        si += self.B.serialize()
        si += self.X.serialize()
        si += Y
        si += 'ntor-curve25519-sha256-1'

        # KEY_SEED = H(secret_input, t_key)
        # verify = H(secret_input, t_verify)
        key_seed = hmac(self.t_key, si)
        verify = hmac(self.t_verify, si)

        # auth_input = verify | ID | B | Y | X | PROTOID | "Server"
        ai = verify
        ai += b64decode(self.node['identity'])
        ai += self.B.serialize()
        ai += Y
        ai += self.X.serialize()
        ai += self.protoid
        ai += 'Server'

        # The client verifies that AUTH == H(auth_input, t_mac).
        if auth != hmac(self.t_mac, ai):
            raise NtorError('auth input does not match.')

        # Both parties check that none of the EXP() operations produced the
        # point at infinity. [NOTE: This is an adequate replacement for
        # checking Y for group membership, if the group is curve25519.]

        # Both parties now have a shared value for KEY_SEED.  They expand this
        # into the keys needed for the Tor relay protocol, using the KDF
        # described in 5.2.2 and the tag m_expand.

        # 5.2.2. KDF-RFC5869

        # For newer KDF needs, Tor uses the key derivation function HKDF from
        # RFC5869, instantiated with SHA256.  (This is due to a construction
        # from Krawczyk.)  The generated key material is:

        #     K = K_1 | K_2 | K_3 | ...

        #     Where H(x,t) is HMAC_SHA256 with value x and key t
        #       and K_1     = H(m_expand | INT8(1) , KEY_SEED )
        #       and K_(i+1) = H(K_i | m_expand | INT8(i+1) , KEY_SEED )
        #       and m_expand is an arbitrarily chosen value,
        #       and INT8(i) is a octet with the value "i".

        # In RFC5869's vocabulary, this is HKDF-SHA256 with info == m_expand,
        # salt == t_key, and IKM == secret_input.
        keys = hkdf(key_seed, length=72, info=self.m_expand)

        # When used in the ntor handshake, the first HASH_LEN bytes form the
        # forward digest Df; the next HASH_LEN form the backward digest Db; the
        # next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final
        # DIGEST_LEN bytes are taken as a nonce to use in the place of KH in the
        # hidden service protocol.  Excess bytes from K are discarded.
        Df, Db, Kf, Kb = struct.unpack('>20s20s16s16s', keys)

        # we do what we can with what we've got.
        del self.X
        del self.x
        del self.B
        del key_seed
        del keys
        del verify
        del ai
        del auth
        del si
        del Y

        self.send_digest = Hash(SHA1(), backend=bend)
        self.send_digest.update(Df)
        self.recv_digest = Hash(SHA1(), backend=bend)
        self.recv_digest.update(Db)

        self.encrypt = Cipher(AES(Kf), CTR('\x00' * 16), backend=bend).encryptor()
        self.decrypt = Cipher(AES(Kb), CTR('\x00' * 16), backend=bend).decryptor()

    def get_handshake(self):
        return self.handshake


