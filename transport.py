import logging
import socket

import cipher_algos
import fields
import mac_algos
from messages import BinarySshPacket


class Transporter:
    logger = logging.getLogger(__name__)
    msg_logger = logging.getLogger(__name__ + '.msg')

    def __init__(self, server_name, server_port):
        self.server_port = server_port
        self.server_name = server_name

        # Init TCP Channel
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_name, self.server_port))
        self.logger.info("TCP connection to %s:%d established" % (self.server_name, self.server_port))

        # Initialize ciphering and integrity checks
        self._ctos_cipher = cipher_algos.NoneCipher()
        self._ctos_mac_algo = mac_algos.NoneMAC()
        self._ctos_sequence_number = 0
        self._stoc_cipher = cipher_algos.NoneCipher()
        self._stoc_mac_algo = mac_algos.NoneMAC()
        self._stoc_sequence_number = 0

    def exchange_versions(self, client_version):
        """Send and receive the SSH protocol and software versions"""

        self.logger.info("Send client version: %s" % client_version)
        self.socket.send((client_version + "\r\n").encode("utf-8"))

        self.logger.debug("Waiting for server version...")
        # Reading a line, until "\r\n"
        version = b""
        previous = b""
        while True:
            current = self.socket.recv(1)
            # The identification MUST be terminated by a single Carriage Return
            # (CR) and a single Line Feed (LF) character (ASCII 13 and 10,
            # respectively).
            if previous == b"\r" and current == b"\n":
                break
            version += previous
            # Implementers who wish to maintain compatibility with older,
            # undocumented versions of this protocol may want to process the
            # identification string without expecting the presence of the
            # carriage return character
            if current == b"\n":
                break
            previous = current
        server_version = version.decode("utf-8")
        self.logger.info("Received server version: %s" % server_version)

        return server_version

    def transmit(self, msg: BinarySshPacket):
        # Format packet
        self.msg_logger.info("Outgoing %s" % msg)
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
        self.msg_logger.info("Incoming %s", ssh_packet)
        return ssh_packet

    def change_keys(self, kex_hash_algo, shared_secret, key_exchange_hash, session_id):
        shared_secret = fields.MpintType().to_bytes(int.from_bytes(shared_secret, 'big', signed=False))
        ctos_iv = kex_hash_algo.hash(
            shared_secret + key_exchange_hash + b"A" + session_id)
        stoc_iv = kex_hash_algo.hash(
            shared_secret + key_exchange_hash + b"B" + session_id)
        ctos_encryption_key = kex_hash_algo.hash(
            shared_secret + key_exchange_hash + b"C" + session_id)
        stoc_encryption_key = kex_hash_algo.hash(
            shared_secret + key_exchange_hash + b"D" + session_id)
        ctos_integrity_key = kex_hash_algo.hash(
            shared_secret + key_exchange_hash + b"E" + session_id)
        stoc_integrity_key = kex_hash_algo.hash(
            shared_secret + key_exchange_hash + b"F" + session_id)
        # TODO: dynamically select algorithms from the Kexinit packet. Here is a hard-coded version.
        self._ctos_cipher = cipher_algos.Aes128Ctr(ctos_iv, ctos_encryption_key)
        self._ctos_mac_algo = mac_algos.HmacSha2_256(ctos_integrity_key)
        self._stoc_cipher = cipher_algos.Aes128Ctr(stoc_iv, stoc_encryption_key)
        self._stoc_mac_algo = mac_algos.HmacSha2_256(stoc_integrity_key)

    def close(self):
        self.socket.close()
