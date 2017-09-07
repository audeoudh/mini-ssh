import logging
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from messages import BinarySshPacket


class NoneMAC:
    name = "none"
    mac_length = 0

    def compute_mac(self, payload):
        return b""

    def check_mac(self, payload, mac):
        return self.compute_mac(payload) == mac


class NoneCipher:
    name = "none"
    block_size = 1

    def encrypt(self, payload):
        return payload

    def decrypt(self, payload):
        return payload


class Transporter:
    logger = logging.getLogger(__name__)

    def __init__(self, server_name, server_port):
        self.server_port = server_port
        self.server_name = server_name

        # Init TCP Channel
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_name, self.server_port))
        self.logger.info("Connexion to %s:%d established" % (self.server_name, self.server_port))

        self._ctos_cipher = NoneCipher()
        self._ctos_mac_algo = NoneMAC()
        self._ctos_sequence_number = 0
        self._stoc_cipher = NoneCipher()
        self._stoc_mac_algo = NoneMAC()
        self._stoc_sequence_number = 0

    def exchange_versions(self, client_version):
        """Send and receive the SSH protocol and software versions"""

        self.logger.info("Send version")
        self.socket.send((client_version + "\r\n").encode("utf-8"))

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
        server_version = version.decode("utf-8")
        self.logger.info("Received server version: %s" % server_version)

        return server_version

    def transmit(self, msg: BinarySshPacket):
        # Format packet
        payload = msg.to_bytes(cipher_block_size=self._ctos_cipher.block_size)
        mac = self._ctos_mac_algo.compute_mac(
            self._ctos_sequence_number.to_bytes(4, 'big') + payload)
        encrypted_data = self._ctos_cipher.encrypt(payload)
        packet = encrypted_data + mac

        # Increase sequence number
        self._ctos_sequence_number += 1
        if self._ctos_sequence_number >= 2 ** 32:
            self._ctos_sequence_number = 0

        # Send data
        self.socket.send(packet)

    def receive(self) -> BinarySshPacket:
        block_size = max(8, self._stoc_cipher.block_size)

        # Receive packet length
        encrypted_data = b""
        while len(encrypted_data) < block_size:
            recv = self.socket.recv(block_size - len(encrypted_data))
            if len(recv) == 0:
                raise Exception("No more data in TCP stream; ssh packet expected")
            encrypted_data += recv
        first_decoded_block = self._stoc_cipher.decrypt(encrypted_data[:block_size])
        p_len = int.from_bytes(first_decoded_block[:4], 'big')

        # Receive data
        while len(encrypted_data) < p_len + 4:
            recv = self.socket.recv(p_len + 4 - len(encrypted_data))
            if len(recv) == 0:
                raise Exception("No more data in TCP stream; ssh packet expected")
            encrypted_data += recv
        payload = first_decoded_block + self._stoc_cipher.decrypt(encrypted_data[block_size:])

        # Receive mac & check it
        msg_mac = b""
        while len(msg_mac) < self._stoc_mac_algo.mac_length:
            recv = self.socket.recv(self._stoc_mac_algo.mac_length - len(msg_mac))
            if len(recv) == 0:
                raise Exception("No more data in TCP stream; ssh packet expected")
            msg_mac += recv
        if not self._stoc_mac_algo.check_mac(
                        self._stoc_sequence_number.to_bytes(4, 'big') + payload, msg_mac):
            raise Exception("Integrity check fails")

        # Increase sequence number
        self._stoc_sequence_number += 1
        if self._stoc_sequence_number >= 2 ** 32:
            self._stoc_sequence_number = 0

        # Parse the packet
        ssh_packet = BinarySshPacket.from_bytes(payload)
        self.logger.info("Received %s", ssh_packet.msg_type.name)
        return ssh_packet

    def close(self):
        self.socket.close()


class AES128_CTR_Transporter(Transporter):
    name = "aes128-ctr"

    def __init__(self, sequence_number, key_bytes, iv_bytes):
        super().__init__(sequence_number)
        self._key = key_bytes[:16]
        IV = iv_bytes[:16]
        self.cipher = Cipher(algorithms.AES(self._key), modes.CTR(IV), backend=default_backend())

    def mangle(self, payload):
        encryptor = self.cipher.encryptor()
        encrypted_data = encryptor.update(payload) + encryptor.finalize()
        mac = MAC(self._mac_key, payload)
        return encrypted_data + mac

    def unmangle(self, encrypted_payload):
        decryptor = self.cipher.decryptor()
        packet_length = decryptor.update(encrypted_payload)
        no_length_payload = decryptor.update(encrypted_payload) + decryptor.finalize()
