# Copyright 2018 Henry-Joseph Audéoud & Timothy Claeys
#
# This file is part of mini-ssh.
#
# mini-ssh is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# mini-ssh is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with mini-ssh.  If not, see
# <https://www.gnu.org/licenses/>.

import abc
import base64

from asn1crypto.algos import DSASignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

import fields


class AuthenticationKey:
    algo_name = None
    known_key_types = {}
    comment = None

    def __init__(self, comment):
        self.comment = comment

    @staticmethod
    def supported_algorithm(algo_name):
        def decorator(cls):
            AuthenticationKey.known_key_types[algo_name] = cls
            cls.algo_name = algo_name
            return cls

        return decorator

    @classmethod
    def from_blob(cls, blob, comment=None):
        # Read key type
        l = int.from_bytes(blob[:4], 'big')
        key_type_name = blob[4:4 + l].decode('ascii')
        try:
            key_type = cls.known_key_types[key_type_name]
        except LookupError:
            raise KeyError("Unknown key type %s" % key_type_name) from None
        else:
            return key_type.from_blob(blob, comment)

    @abc.abstractmethod
    def sign(self, data):
        ...

    @abc.abstractmethod
    def public_blob(self):
        ...

    def fingerprint(self, hash_algo):
        blob = self.public_blob()
        hash_algo_name = str(hash_algo.name).upper()
        digest = hash_algo.hash(blob)
        digest = base64.encodebytes(digest).decode('ascii')
        digest = digest.rstrip('\n=')
        return "%s:%s" % (hash_algo_name, digest)

    def _format_public_blob(self, blob):
        return fields.StringType('ascii').to_bytes(self.algo_name) + blob

    def _format_signature(self, data):
        return fields.StringType('ascii').to_bytes(self.algo_name) + \
               fields.StringType('octet').to_bytes(data)


@AuthenticationKey.supported_algorithm("ssh-rsa")
class Rsa(AuthenticationKey):
    @classmethod
    def from_blob(cls, blob, comment=None):
        blob = iter(blob)
        algo_name, e, n = \
            fields.StringType('ascii').from_bytes(blob), \
            fields.MpintType().from_bytes(blob), \
            fields.MpintType().from_bytes(blob)
        pub_n = rsa.RSAPublicNumbers(e, n)
        return cls(None, pub_n.public_key(default_backend()), comment)

    def __init__(self, private_key, public_key, comment):
        super().__init__(comment)
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, data):
        return super()._format_signature(
            self.private_key.sign(data, padding.PKCS1v15(), hashes.SHA1()))

    def public_blob(self):
        pub_n = self.public_key.public_numbers()
        return self._format_public_blob(
            fields.MpintType().to_bytes(pub_n.e) +
            fields.MpintType().to_bytes(pub_n.n))

    def __eq__(self, other):
        if not isinstance(other, Rsa):
            return NotImplemented
        return self.public_key.public_numbers() == other.public_key.public_numbers()


class Ecdsa(AuthenticationKey):
    curve_name = None
    curve = None
    hash_algo = None

    @classmethod
    def from_blob(cls, blob, comment=None):
        blob = iter(blob)
        cname, algo, encoded_point = \
            fields.StringType('ascii').from_bytes(blob), \
            fields.StringType('ascii').from_bytes(blob), \
            fields.StringType('octet').from_bytes(blob)
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(cls.curve, encoded_point)
        return cls(None, pub_key, comment)

    def __init__(self, private_key, public_key, comment=None):
        super().__init__(comment)
        self.private_key = private_key
        self.public_key = public_key

    def sign(self, data):
        signature = self.private_key.sign(data, ec.ECDSA(self.hash_algo))
        data = DSASignature.load(signature, strict=True).native
        r, s = data['r'], data['s']
        return super()._format_signature(
            fields.MpintType().to_bytes(r) +
            fields.MpintType().to_bytes(s))

    def public_blob(self):
        return self._format_public_blob(
            fields.StringType('ascii').to_bytes(self.curve_name) +
            fields.StringType('octet').to_bytes(
                self.public_key.public_numbers().encode_point()))


_correspondance_ssh_pyca = {
    'nistp256': (ec.SECP256R1(), hashes.SHA256()),
    'nistp384': (ec.SECP384R1(), hashes.SHA384()),
    'nistp521': (ec.SECP521R1(), hashes.SHA512()),
    'nistk163': (ec.SECT163K1(), hashes.SHA256()),
    'nistp192': (ec.SECP192R1(), hashes.SHA256()),
    'nistp224': (ec.SECP224R1(), hashes.SHA256()),
    'nistk233': (ec.SECT233K1(), hashes.SHA256()),
    'nistb233': (ec.SECT233R1(), hashes.SHA256()),
    'nistk283': (ec.SECT283K1(), hashes.SHA256()),
    'nistk409': (ec.SECT409K1(), hashes.SHA512()),
    'nistb409': (ec.SECT409R1(), hashes.SHA512()),
    'nistt571': (ec.SECT571K1(), hashes.SHA512()),
}

for curve_name, (curve, hash_algo) in _correspondance_ssh_pyca.items():
    AuthenticationKey.supported_algorithm("ecdsa-sha2-%s" % curve_name)(
        type("%sEcdsa" % curve_name, (Ecdsa,),
             dict(curve_name=curve_name,
                  curve=curve,
                  hash_algo=hash_algo)))
