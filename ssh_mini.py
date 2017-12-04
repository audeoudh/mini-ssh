import logging
import os

import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

import fields
import hash_algos
from messages import *
from transport import Transporter


class SshConnection:
    logger = logging.getLogger(__name__)

    client_version = "SSH-2.0-python_tim&henry_1.0"

    def __init__(self, user_name, server_name, port=22):
        self.user_name = user_name
        self.server_name = server_name
        self.port = port
        self.transporter = None
        self._session_id = None

    @property
    def session_id(self):
        """The session identifier. If the session is not currently initialized, None."""
        return self._session_id

    def __enter__(self):
        # Start transport layer
        self.transporter = Transporter(self.server_name, self.port)

        # Compute the session identifier

        # Server's ephemeral public key param
        self.point_encoded_server_epub = None
        self.server_epub_key = None

        # Start SSH connection
        self._version()
        self._key_exchange()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close()

    def _version(self):
        self.server_version = self.transporter.exchange_versions(self.client_version)

    def _key_exchange(self):
        """Do a whole key exchange, as described in RFC 4253"""
        self.logger.info("Exchange key mechanism activated...")

        # Compute some locally chosen values
        self._ephemeral_private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
        cookie = os.urandom(16)

        # Key Exchange Init: exchange the supported crypto algorithms
        client_kexinit = KexInit(
            cookie=cookie,
            kex_algo=("ecdh-sha2-nistp256",), server_host_key_algo=("ssh-rsa",),
            encryption_algo_ctos=("aes128-ctr",), encryption_algo_stoc=("aes128-ctr",),
            mac_algo_ctos=("hmac-sha2-256",), mac_algo_stoc=("hmac-sha2-256",),
            compression_algo_ctos=("none",), compression_algo_stoc=("none",),
            languages_ctos=(), languages_stoc=(),
            first_kex_packet_follows=False)
        self.transporter.transmit(client_kexinit)
        server_kexinit = self.transporter.receive()
        if not isinstance(server_kexinit, KexInit):
            raise Exception("First packet is not a KEI packet")
        self.logger.info("Key Exchange Init phase: ok")

        # Key Exchange Diffie-Hellman: create a shared secret
        client_kex_ecdh = KexDHInit(
            e=self._ephemeral_private_key.public_key().public_numbers().encode_point())
        self.transporter.transmit(client_kex_ecdh)
        server_kex_ecdh = self.transporter.receive()
        if not isinstance(server_kex_ecdh, KexDHReply):
            raise Exception("not a KEXDH_REPLY packet")

        kex_hash_algo = hash_algos.EcdhSha2Nistp256()  # Currently forced. TODO: make it modifiable

        # construct a 'public key' object from the received server public key
        curve = ec.SECP256R1()
        self._server_ephemeral_public_key = \
            ec.EllipticCurvePublicNumbers.from_encoded_point(curve, server_kex_ecdh.f) \
                .public_key(default_backend())

        # multiply server's ephemeral public key with client's ephemeral private key --> shared secret
        shared_secret = self._ephemeral_private_key.exchange(ec.ECDH(), self._server_ephemeral_public_key)
        self.logger.info("Key Exchange Diffie-Hellman phase: ok")

        # Compute exchange hash
        class ExchangeHash(BinarySshPacket):
            # Not really a SSH packet, but we use the same method to get the payload.

            __slots__ = ('client_version', 'server_version',
                         'client_kexinit', 'server_kexinit',
                         'host_key',
                         'client_exchange_value', 'server_exchange_value',
                         'shared_secret')

            _fields_type = (StringType('ascii'), StringType('ascii'),
                            StringType('octet'), StringType('octet'),
                            StringType('octet'),
                            StringType('octet'), StringType('octet'),
                            MpintType())

        client_kexinit_bytes = client_kexinit.msg_type.to_bytes(1, 'big') + client_kexinit.payload()
        server_kexinit_bytes = server_kexinit.msg_type.to_bytes(1, 'big') + server_kexinit.payload()
        to_be_hashed = ExchangeHash(
            client_version=self.client_version, server_version=self.server_version,
            client_kexinit=client_kexinit_bytes, server_kexinit=server_kexinit_bytes,
            host_key=server_kex_ecdh.server_public_key,
            client_exchange_value=client_kex_ecdh.e, server_exchange_value=server_kex_ecdh.f,
            shared_secret=int.from_bytes(shared_secret, 'big', signed=False))
        key_exchange_hash = kex_hash_algo.hash(to_be_hashed.payload())

        # Set the session ID:
        # > The exchange hash H from the first key exchange is additionally
        # > used as the session identifier [...] Once computed, the session
        # > identifier is not changed, even if keys are later re-exchanged
        # > [RFC4253]
        if self._session_id is None:
            self._session_id = key_exchange_hash

        # Verify server's signature
        server_public_key_iterator = server_kex_ecdh.server_public_key.__iter__()
        key_type = fields.StringType('ascii').from_bytes(server_public_key_iterator)
        # TODO: support other key types. Here, only ssh-rsa keys are supported.
        assert key_type == 'ssh-rsa'
        rsa_exponent = fields.MpintType().from_bytes(server_public_key_iterator)
        rsa_modulus = fields.MpintType().from_bytes(server_public_key_iterator)
        server_key = rsa.RSAPublicNumbers(e=rsa_exponent, n=rsa_modulus).public_key(default_backend())

        server_signature_iterator = server_kex_ecdh.signature.__iter__()
        key_type = fields.StringType('ascii').from_bytes(server_signature_iterator)
        # TODO: support other key types. Here, only ssh-rsa keys are supported.
        assert key_type == 'ssh-rsa'
        signature = fields.StringType('octet').from_bytes(server_signature_iterator)

        server_key.verify(signature, key_exchange_hash, padding.PKCS1v15(), hashes.SHA1())
        self.logger.info("Server signature verification: ok")

        # New Keys: switch to the new cyphering method
        self.transporter.transmit(NewKeys())
        nk = self.transporter.receive()
        if not isinstance(nk, NewKeys):
            raise Exception("not a NEWKEYS packet")

        # Activate the encryption
        self.transporter.change_keys(kex_hash_algo, shared_secret, key_exchange_hash, self.session_id)
        self.logger.info("Keys and algorithms change: ok")

    def _close(self):
        self.transporter.close()


@click.command()
@click.argument("remote")
@click.option("-p", required=False, default=22)
def main(remote, p=22):
    parts = remote.split("@")
    if len(parts) == 1:
        user_name = "root"  # TODO: better to extract the username from environment
        server_name = remote
    elif len(parts) == 2:
        user_name = parts[0]
        server_name = parts[1]
    else:
        raise Exception("Unable to find user & server name")

    with SshConnection(user_name, server_name, p) as sshc:
        print("Established")


if __name__ == "__main__":
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
    main()
