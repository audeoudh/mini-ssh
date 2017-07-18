import logging
import socket

import click


class BinarySshPacket:
    @classmethod
    def from_bytes(cls, flow):
        packet_len = int.from_bytes(flow[0:4], 'big')
        padding_length = int.from_bytes(flow[4:5], 'big')
        payload = flow[5:(5 + packet_len - padding_length - 1)]
        padding = flow[(5 + packet_len - padding_length - 1):(5 + packet_len - 1)]
        mac = flow[(5 + packet_len - 1):]

        # We only know how to decode KEI messages
        return KexinitSshPacket.from_bytes(payload)

    @classmethod
    def _list_from_bytes(cls, flow):
        list_len = int.from_bytes(flow[:4], "big")
        return list_len, flow[4:(4 + list_len)].decode("utf-8").split(",")

    @classmethod
    def _list_to_bytes(cls, value):
        value = ",".join(value)
        value = value.encode("utf-8")
        return len(value).to_bytes(4, "big") + value

    def _to_bytes(self, payload):
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


class KexinitSshPacket(BinarySshPacket):
    SSH_MSG_KEXINIT = 0x14

    @classmethod
    def from_bytes(cls, flow):
        if not flow[0] == cls.SSH_MSG_KEXINIT:
            raise Exception("Message is not a KEXINIT message")
        cookie = flow[1:17]
        i = 17
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
        message = self.SSH_MSG_KEXINIT.to_bytes(1, 'big')
        message += self.cookie
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
        self.socket_w = self.socket.makefile(mode="wb")
        self.socket_r = self.socket.makefile(mode="rb")

        # Start SSH connection
        self._version()
        self._kei()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()

    def _version(self):
        self.logger.info("Send version")
        self.write(b"SSH-2.0-pyhton_tim&henry_1.0\r\n")

        self.logger.info("Waiting for server version...")
        version = self.socket_r.readline().decode("utf-8")[:-2]
        self.logger.info("Found server version: %s" % version)
        return version

    def _kei(self):
        self.logger.info("Send KEI message")
        message = KexinitSshPacket()
        self.write(message.to_bytes())

        self.logger.info("Waiting for server KEI...")
        data = self.socket_r.read()
        kei = BinarySshPacket.from_bytes(data)
        if not isinstance(kei, KexinitSshPacket):
            raise Exception("First packet is not a KEI packet")
        logging.info("Found server KEI")

    def write(self, content):
        if isinstance(content, str):
            self.socket_w.write(content.encode("utf-8"))
        else:
            self.socket_w.write(content)
        self.socket_w.flush()


@click.command()
@click.argument("server_name")
@click.option("-p", required=False, default=22)
def main(server_name, p=22):
    with SshConnection(server_name, p) as sshc:
        sshc.write("foo")


if __name__ == "__main__":
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
    main()
