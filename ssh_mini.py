import logging
import socket

import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from messages import *


class SshConnection:
    logger = logging.getLogger(__name__)

    client_version = "SSH-2.0-python_tim&henry_1.0"

    def __init__(self, user_name, server_name, port=22):
        self.user_name = user_name
        self.server_name = server_name
        self.port = port
        self.master_secret = None

    def __enter__(self):
        # Init TCP Channel
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_name, self.port))
        self.logger.info("Connexion to %s:%d established" % (self.server_name, self.port))

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
        self.socket.close()

    def _version(self):
        """Send and receive the SSH protocol and software versions"""

        self.logger.info("Send version")
        self.write((self.client_version + "\r\n").encode("utf-8"))

        self.logger.debug("Waiting for server version...")
        # Reading a line, until "\r\n"
        version = b""
        previous = b""
        while True:
            current = self.socket.recv(1)
            if previous == b"\r" and current == b"\n":
                break
            version += previous
            previous = current
        self.server_version = version.decode("utf-8")
        self.logger.info("Received server version: %s" % self.server_version)

    def _key_exchange(self):
        """Do a whole key exchange, as described in RFC 4253"""
        self._ephemeral_private_key = ec.generate_private_key(ec.SECP256R1, default_backend())

        # Key Exchange Init: exchange the supported crypto algorithms
        self.logger.info("Send KEI message")
        message = KexinitSshPacket(cookie=self.session_id)
        self.write(message.to_bytes())

        self.logger.debug("Waiting for server KEI...")
        kei = self.recv_ssh_packet()
        if not isinstance(kei, KexinitSshPacket):
            raise Exception("First packet is not a KEI packet")

        # Key Exchange Diffie-Hellman: create a shared secret
        self.logger.info("Send KEX_ECDH_INIT message")
        message = KexSshPacket(self._ephemeral_private_key.public_key())
        self.write(message.to_bytes())

        self.logger.debug("Waiting for server's KEXDH_REPLY")
        kex = self.recv_ssh_packet()
        if not isinstance(kex, KexdhReplySshPacket):
            raise Exception("not a KEXDH_REPLY packet")
        point_encoded_server_epub = kex.f

        # construct a 'public key' object from the received server public key
        curve = ec.SECP256R1()
        self._server_ephemeral_public_key = \
            ec.EllipticCurvePublicNumbers.from_encoded_point(curve, point_encoded_server_epub) \
                .public_key(default_backend())

        # multiply server's ephemeral public key with client's ephemeral private key --> master secret
        master_secret = self._ephemeral_private_key.exchange(ec.ECDH(), self._server_ephemeral_public_key)

        # New Keys: switch to the new cyphering method
        self.logger.info("Send NEWKEYS")
        self.write(NewKeysSshPacket().to_bytes())

        nk = self.recv_ssh_packet()
        if not isinstance(nk, NewKeysSshPacket):
            raise Exception("not a NEWKEYS packet")

        # Activate the encryption
        self.master_secret = master_secret

    def write(self, content):
        if isinstance(content, str):
            self.socket.send(content.encode("utf-8"))
        else:
            self.socket.send(content)

    def recv_ssh_packet(self):
        # Receive packet length
        packet_len = b""
        while len(packet_len) < 4:
            recv = self.socket.recv(4 - len(packet_len))
            if len(recv) == 0:
                raise Exception("No more data in TCP stream; ssh packet expected")
            packet_len += recv
        p_len = int.from_bytes(packet_len, "big")

        # Receive data
        packet = b""
        while len(packet) < p_len:
            recv = self.socket.recv(p_len - len(packet))
            if len(recv) == 0:
                raise Exception("No more data in TCP stream; ssh packet expected")
            packet += recv

        # Decode packet
        ssh_packet = BinarySshPacket.from_bytes(packet_len + packet)
        self.logger.info("Received %s", ssh_packet.msg_type.name)
        return ssh_packet


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
        sshc.write("foo")


if __name__ == "__main__":
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
    main()
