import hashlib
import logging
import os

import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

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

    def __enter__(self):
        # Start transport layer
        self.transporter = Transporter(self.server_name, self.port)

        # Compute the session identifier
        self.session_id = os.urandom(16)

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
        self._ephemeral_private_key = ec.generate_private_key(ec.SECP256R1, default_backend())

        # Key Exchange Init: exchange the supported crypto algorithms
        self.logger.info("Send KEI message")
        client_kexinit = KexinitSshPacket(cookie=self.session_id)
        self.transporter.transmit(client_kexinit)

        self.logger.debug("Waiting for server KEI...")
        server_kexinit = self.transporter.receive()
        if not isinstance(server_kexinit, KexinitSshPacket):
            raise Exception("First packet is not a KEI packet")

        # Key Exchange Diffie-Hellman: create a shared secret
        self.logger.info("Send KEX_ECDH_INIT message")
        client_kex_ecdh = KexSshPacket(self._ephemeral_private_key.public_key().public_numbers().encode_point())
        self.transporter.transmit(client_kex_ecdh)

        self.logger.debug("Waiting for server's KEXDH_REPLY")
        server_kex_ecdh = self.transporter.receive()
        if not isinstance(server_kex_ecdh, KexdhReplySshPacket):
            raise Exception("not a KEXDH_REPLY packet")
        point_encoded_server_epub = server_kex_ecdh.f

        # construct a 'public key' object from the received server public key
        curve = ec.SECP256R1()
        self._server_ephemeral_public_key = \
            ec.EllipticCurvePublicNumbers.from_encoded_point(curve, point_encoded_server_epub) \
                .public_key(default_backend())

        # multiply server's ephemeral public key with client's ephemeral private key --> shared secret
        shared_secret = self._ephemeral_private_key.exchange(ec.ECDH(), self._server_ephemeral_public_key)

        # Compute exchange hash
        # FIXME: not sure these are the correct formula
        to_be_hashed = \
            BinarySshPacket._string_to_bytes(self.client_version, 'ascii') + \
            BinarySshPacket._string_to_bytes(self.server_version, 'ascii') + \
            BinarySshPacket._string_to_bytes(SshMsgType.SSH_MSG_KEXINIT.to_bytes(1, 'big') + client_kexinit.payload_bytes(), 'octet') + \
            BinarySshPacket._string_to_bytes(SshMsgType.SSH_MSG_KEXINIT.to_bytes(1, 'big') + server_kexinit.payload_bytes(), 'octet') + \
            BinarySshPacket._string_to_bytes(server_kex_ecdh.server_key, 'octet') + \
            BinarySshPacket._string_to_bytes(self._ephemeral_private_key.public_key().public_numbers().encode_point(), 'octet') + \
            BinarySshPacket._string_to_bytes(server_kex_ecdh.f, 'octet') + \
            BinarySshPacket._mpint_to_bytes(shared_secret, 32)

        key_exchange_hash = hashlib.sha256(to_be_hashed).digest()

        # Verify server's signature
        i = 0
        read_len, key_type = BinarySshPacket._string_from_bytes(server_kex_ecdh.server_key[i:], encoding="ascii")
        # TODO: support other key types. Here, only ssh-rsa keys are supported.
        assert key_type == 'ssh-rsa'
        i += read_len
        read_len, rsa_exponent = BinarySshPacket._mpint_from_bytes(server_kex_ecdh.server_key[i:])
        i += read_len
        _, rsa_modulus = BinarySshPacket._mpint_from_bytes(server_kex_ecdh.server_key[i:])
        server_key = rsa.RSAPublicNumbers(rsa_exponent, rsa_modulus).public_key(default_backend())

        i = 0
        read_len, key_type = BinarySshPacket._string_from_bytes(server_kex_ecdh.f_sig[i:], encoding="ascii")
        # TODO: support other key types. Here, only ssh-rsa keys are supported.
        assert key_type == 'ssh-rsa'
        i += read_len
        _, signature = BinarySshPacket._string_from_bytes(server_kex_ecdh.f_sig[i:], encoding="octet")

        # Verify the signature
        server_key.verify(signature, key_exchange_hash, padding.PKCS1v15(), hashes.SHA1())

        # New Keys: switch to the new cyphering method
        self.logger.info("Send NEWKEYS")
        self.transporter.transmit(NewKeysSshPacket())

        nk = self.transporter.receive()
        if not isinstance(nk, NewKeysSshPacket):
            raise Exception("not a NEWKEYS packet")

        # Activate the encryption
        self.shared_secret = shared_secret


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
