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

import logging
import socket

import cipher_algos
import fields
import mac_algos
from messages import BinarySshPacket


class Transport(socket.socket):
    """Implements the entire SSH transport layer, as defined in RFC4253.

    This class instantiates a TCP socket and sets up the transport layer for the SSH protocol. The Transport class
    sends & receives a stream encoded as BinarySshPacket tokens. It supports encryption & MAC verification."""

    logger = logging.getLogger(__name__)
    msg_logger = logging.getLogger(__name__ + '.msg')

    def __init__(self):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.server_name, self.server_port = None, None

        # Initialize ciphering and integrity checks
        self._ctos_cipher = cipher_algos.NoneCipher()
        self._ctos_mac_algo = mac_algos.NoneMAC()
        self._ctos_sequence_number = 0
        self._stoc_cipher = cipher_algos.NoneCipher()
        self._stoc_mac_algo = mac_algos.NoneMAC()
        self._stoc_sequence_number = 0

    def connect(self, address):
        self.server_name, self.server_port = address
        super().connect((self.server_name, self.server_port))
        self.logger.info("TCP connection to %s:%d established" % (self.server_name, self.server_port))

    def exchange_versions(self, client_version):
        """Send and receive the SSH protocol and software versions

        :return The server version"""

        self.logger.info("Send client version: %s" % client_version)
        self.send((client_version + "\r\n").encode("utf-8"))

        self.logger.debug("Waiting for server version...")
        # Reading a line, until "\r\n"
        version = b""
        previous = b""
        while True:
            current = self.recv(1)
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

    def send_ssh_msg(self, msg: BinarySshPacket):
        """Send a packet.

        :param msg: The SSH message to be sent"""
        # Format packet
        if self.msg_logger.isEnabledFor(logging.DEBUG):
            self.msg_logger.debug("Outgoing %r" % msg)
        else:
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
        self.send(packet)

    def recv_ssh_msg(self) -> BinarySshPacket:
        """Receive a SSH packet.

        :return The received packet, or None if no packet is available (this
          may happen even if the socket is readable: some TCP data may have
          been read without a full SSH packet be available).

        :raise Exception if the connection is closed while reading a packet.

        :raise Exception if the MAC is wrong."""
        block_size = max(8, self._stoc_cipher.block_size)

        # Receive packet length
        encrypted_data = b""
        while len(encrypted_data) < block_size:
            recv = self.recv(block_size - len(encrypted_data))
            if len(recv) == 0:
                raise Exception("No more data in TCP stream; ssh packet expected")
            encrypted_data += recv
        first_decoded_block = self._stoc_cipher.decrypt(encrypted_data[:block_size])
        p_len = int.from_bytes(first_decoded_block[:4], 'big')

        # Receive data
        while len(encrypted_data) < p_len + 4:
            recv = self.recv(p_len + 4 - len(encrypted_data))
            if len(recv) == 0:
                raise Exception("No more data in TCP stream; ssh packet expected")
            encrypted_data += recv
        payload = first_decoded_block + self._stoc_cipher.decrypt(encrypted_data[block_size:])

        # Receive mac & check it
        msg_mac = b""
        while len(msg_mac) < self._stoc_mac_algo.mac_length:
            recv = self.recv(self._stoc_mac_algo.mac_length - len(msg_mac))
            if len(recv) == 0:
                raise Exception("No more data in TCP stream; ssh packet expected")
            msg_mac += recv
        self._stoc_mac_algo.check_mac(self._stoc_sequence_number.to_bytes(4, 'big') + payload, msg_mac)

        # Increase sequence number
        self._stoc_sequence_number += 1
        if self._stoc_sequence_number >= 2 ** 32:
            self._stoc_sequence_number = 0

        # Parse the packet
        ssh_packet = BinarySshPacket.from_bytes(payload)
        if self.msg_logger.isEnabledFor(logging.DEBUG):
            self.msg_logger.debug("Incoming %r", ssh_packet)
        else:
            self.msg_logger.info("Incoming %s", ssh_packet)
        return ssh_packet

    def change_keys(self, kex_hash_algo, shared_secret, key_exchange_hash, session_id):
        """Renew the crypto keys and algorithms."""
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
