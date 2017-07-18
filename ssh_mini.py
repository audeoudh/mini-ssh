import logging
import socket

import click


class BinarySshPacket:
    SSH_MSG_KEXINIT = 0x14
    SSH_MSG_KEXDH_INIT = 0x1e
    SSH_MSG_KEXDH_REPLY = 0x1f

    msg_type = None  # Should be filled by subclasses

    _msg_types = {}

    @classmethod
    def packet_metaclass(cls, name, bases, clsdict):
        the_class = type(name, bases, clsdict)
        cls._msg_types[the_class.msg_type] = the_class
        return the_class

    @classmethod
    def from_bytes(cls, flow):
        packet_len = int.from_bytes(flow[0:4], 'big')
        padding_length = flow[4]
        msg_type = flow[5]
        payload = flow[6:(6 + packet_len - padding_length - 1)]
        padding = flow[(6 + packet_len - padding_length - 1):(6 + packet_len - 1)]
        mac = flow[(6 + packet_len - 1):]

        return cls._msg_types[msg_type].from_bytes(payload)

    @classmethod
    def _field_from_bytes(cls, flow):
        field_len = int.from_bytes(flow[:4], "big")
        field = flow[4:(4 + field_len)]
        return field_len, field

    @classmethod
    def _field_to_bytes(cls, value):
        return len(value).to_bytes(4, "big") + value

    @classmethod
    def _list_from_bytes(cls, flow):
        list_len, list_ = cls._field_from_bytes(flow)
        list_ = list_.decode("utf-8").split(",")
        return list_len, list_

    @classmethod
    def _list_to_bytes(cls, value):
        value = ",".join(value)
        value = value.encode("utf-8")
        return cls._field_to_bytes(value)

    @classmethod
    def _mpint_from_bytes(cls, flow):
        mpi_len, mpi = cls._field_from_bytes(flow)
        mpi = int.from_bytes(mpi, 'big')
        return mpi_len, mpi

    @classmethod
    def _mpint_to_bytes(cls, value, mpi_len=None):
        if mpi_len is None:
            mpi_len = (value.bit_length() + 7) // 8
        mpi = value.to_bytes(mpi_len, 'big')
        return mpi_len.to_bytes(4, 'big') + mpi

    def _to_bytes(self, payload):
        payload = self.msg_type.to_bytes(1, 'big') + payload

        # Padding
        _CIPHER_BLOCK_SIZE = 8
        pckt_len = 4 + 1 + len(payload)
        if pckt_len < max(16, _CIPHER_BLOCK_SIZE):
            pad_len = max(16, _CIPHER_BLOCK_SIZE) - pckt_len
        else:
            pad_len = _CIPHER_BLOCK_SIZE - pckt_len % _CIPHER_BLOCK_SIZE
        if pad_len < 4:
            pad_len += _CIPHER_BLOCK_SIZE
        packet = pad_len.to_bytes(1, 'big') + payload + b"\00" * pad_len

        # Packet length
        packet = len(packet).to_bytes(4, 'big') + packet

        # Not Yet Implemented: MAC field

        return packet


class KexinitSshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = BinarySshPacket.SSH_MSG_KEXINIT

    @classmethod
    def from_bytes(cls, flow):
        cookie = flow[0:16]
        i = 16
        list_len, kex_algo = cls._list_from_bytes(flow[i:])
        i += list_len + 4
        list_len, server_host_key_algo = cls._list_from_bytes(flow[i:])
        i += list_len + 4
        list_len, encryption_algo_ctos = cls._list_from_bytes(flow[i:])
        i += list_len + 4
        list_len, encryption_algo_stoc = cls._list_from_bytes(flow[i:])
        i += list_len + 4
        list_len, mac_algo_ctos = cls._list_from_bytes(flow[i:])
        i += list_len + 4
        list_len, mac_algo_stoc = cls._list_from_bytes(flow[i:])
        i += list_len + 4
        list_len, compression_algo_ctos = cls._list_from_bytes(flow[i:])
        i += list_len + 4
        list_len, compression_algo_stoc = cls._list_from_bytes(flow[i:])
        i += list_len + 4
        list_len, languages_ctos = cls._list_from_bytes(flow[i:])
        i += list_len + 4
        _, languages_stoc = cls._list_from_bytes(flow[i:])

        return cls(cookie, kex_algo, server_host_key_algo, encryption_algo_ctos, encryption_algo_stoc,
                   mac_algo_ctos, mac_algo_stoc, compression_algo_ctos, compression_algo_stoc,
                   languages_ctos, languages_stoc)

    def __init__(self, cookie=b"\x02" * 16,
                 kex_algo=None, server_host_key_algo=None,
                 encryption_algo_ctos=None, encryption_algo_stoc=None,
                 mac_algo_ctos=None, mac_algo_stoc=None,
                 compression_algo_ctos=None, compression_algo_stoc=None,
                 languages_ctos=None, languages_stoc=None):
        super(KexinitSshPacket, self).__init__()
        if kex_algo is None:
            kex_algo = ["curve25519-sha256@libssh.org"]
        if server_host_key_algo is None:
            server_host_key_algo = ["ssh-rsa"]
        if encryption_algo_ctos is None:
            encryption_algo_ctos = ["laes128-ctr", "aes192-ctr"]
        if encryption_algo_stoc is None:
            encryption_algo_stoc = ["laes128-ctr", "aes192-ctr"]
        if mac_algo_ctos is None:
            mac_algo_ctos = ["umac-64-etm@openssh.com"]
        if mac_algo_stoc is None:
            mac_algo_stoc = ["umac-64-etm@openssh.com"]
        if compression_algo_ctos is None:
            compression_algo_ctos = ["none"]
        if compression_algo_stoc is None:
            compression_algo_stoc = ["none"]
        if languages_ctos is None:
            languages_ctos = []
        if languages_stoc is None:
            languages_stoc = []
        self.cookie = cookie
        self.kex_algo = kex_algo
        self.server_host_key_algo = server_host_key_algo
        self.encryption_algo_ctos = encryption_algo_ctos
        self.encryption_algo_stoc = encryption_algo_stoc
        self.mac_algo_ctos = mac_algo_ctos
        self.mac_algo_stoc = mac_algo_stoc
        self.compression_algo_ctos = compression_algo_ctos
        self.compression_algo_stoc = compression_algo_stoc
        self.languages_ctos = languages_ctos
        self.languages_stoc = languages_stoc

    def to_bytes(self):
        message = self.cookie
        message += self._list_to_bytes(self.kex_algo)
        message += self._list_to_bytes(self.server_host_key_algo)
        message += self._list_to_bytes(self.encryption_algo_ctos)
        message += self._list_to_bytes(self.encryption_algo_stoc)
        message += self._list_to_bytes(self.mac_algo_ctos)
        message += self._list_to_bytes(self.mac_algo_stoc)
        message += self._list_to_bytes(self.compression_algo_ctos)
        message += self._list_to_bytes(self.compression_algo_stoc)
        message += self._list_to_bytes(self.languages_ctos)
        message += self._list_to_bytes(self.languages_stoc)
        message += b"\x00"  # KEX first packet follows: FALSE
        message += int(0).to_bytes(4, 'big')  # reserved

        return self._to_bytes(message)


class KexSshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = BinarySshPacket.SSH_MSG_KEXDH_INIT

    def __init__(self, e):
        super(KexSshPacket, self).__init__()
        self.e = e

    def to_bytes(self):
        message = self._mpint_to_bytes(self.e, 32)
        return self._to_bytes(message)


class KexdhReplySshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = BinarySshPacket.SSH_MSG_KEXDH_REPLY

    @classmethod
    def from_bytes(cls, flow):
        i = 0
        size, server_key = cls._field_from_bytes(flow[i:])
        i += size + 4
        size, f = cls._mpint_from_bytes(flow[i:])
        i += size + 4
        _, f_sig = cls._field_from_bytes(flow[i:])
        return cls(server_key, f, f_sig)

    def __init__(self, server_key, f, f_sig):
        super(KexdhReplySshPacket, self).__init__()
        self.server_key = server_key
        self.f = f
        self.f_sig = f_sig


class SshConnection:
    logger = logging.getLogger(__name__)

    def __init__(self, server_name, port=22):
        self.server_name = server_name
        self.port = port

    def __enter__(self):
        # init TCP Channel
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_name, self.port))
        self.logger.info("Connexion to %s:%d established" % (self.server_name, self.port))

        # Start SSH connection
        self._version()
        self._kei()
        self._kexdh()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()

    def _version(self):
        self.logger.info("Send version")
        self.write(b"SSH-2.0-pyhton_tim&henry_1.0\r\n")

        self.logger.info("Waiting for server version...")
        # Reading a line, until "\r\n"
        version = b""
        previous = b""
        while True:
            current = self.socket.recv(1)
            if previous == b"\r" and current == b"\n":
                break
            version += previous
            previous = current
        version = version.decode("utf-8")
        self.logger.info("Found server version: %s" % version)
        return version

    def _kei(self):
        self.logger.info("Send KEI message")
        message = KexinitSshPacket()
        self.write(message.to_bytes())

        self.logger.info("Waiting for server KEI...")
        kei = self.recv_ssh_packet()
        if not isinstance(kei, KexinitSshPacket):
            raise Exception("First packet is not a KEI packet")
        logging.info("Found server KEI")

    def _kexdh(self):
        self.logger.info("Send KEXDH_INIT message")
        message = KexSshPacket(0x17)  # TODO: select a correct random 'e' value
        self.write(message.to_bytes())

        self.logger.info("Waiting for server's KEXDH_REPLY")
        kex = self.recv_ssh_packet()
        if not isinstance(kex, KexdhReplySshPacket):
            raise Exception("First packet is not a KEXDH_REPLY packet")
        logging.info("Found server KEXDH_REPLY")

    def write(self, content):
        if isinstance(content, str):
            self.socket.send(content.encode("utf-8"))
        else:
            self.socket.send(content)

    def recv_ssh_packet(self):
        packet_len = self.socket.recv(4)
        if packet_len == b"":
            raise Exception("No more data in TCP stream; ssh packet expected")
        data = self.socket.recv(int.from_bytes(packet_len, "big"))
        return BinarySshPacket.from_bytes(packet_len + data)


@click.command()
@click.argument("server_name")
@click.option("-p", required=False, default=22)
def main(server_name, p=22):
    with SshConnection(server_name, p) as sshc:
        sshc.write("foo")


if __name__ == "__main__":
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
    main()
