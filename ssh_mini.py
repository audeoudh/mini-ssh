import socket
from contextlib import closing


class BinarySshPacket:
    @classmethod
    def from_bytes(cls, flow):
        packet_len = int.from_bytes(flow[0:4], 'big')
        padding_length = int.from_bytes(flow[4:5], 'big')
        payload = flow[5:(5 + packet_len - padding_length - 1)]
        padding = flow[(5 + packet_len - padding_length - 1):(5 + packet_len - 1)]
        mac = flow[(5 + packet_len - 1):]

        # We only know how to decode KEI messages
        return KeiSshPacket.from_bytes(payload)

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


class KeiSshPacket(BinarySshPacket):
    SSH_MSG_KEXINIT = 0x14

    @classmethod
    def from_bytes(cls, flow):
        if not flow[0] == cls.SSH_MSG_KEXINIT:
            raise Exception("Message is not a KEXINIT message")
        cookie = flow[1:17]
        i = 17

        def extract_string(start):
            strlen = int.from_bytes(flow[start:start + 4], 'big')
            return flow[(start + 4):(start + 4 + strlen)]

        kex_algo = extract_string(i)
        i += len(kex_algo)
        server_host_key_algo = extract_string(i)
        i += len(kex_algo)
        encryption_algo_ctos = extract_string(i)
        i += len(kex_algo)
        encryption_algo_stoc = extract_string(i)
        i += len(kex_algo)
        mac_algo_ctos = extract_string(i)
        i += len(kex_algo)
        mac_algo_stoc = extract_string(i)
        i += len(kex_algo)
        compression_algo_ctos = extract_string(i)
        i += len(kex_algo)
        compression_algo_stoc = extract_string(i)
        i += len(kex_algo)
        languages_ctos = extract_string(i)
        i += len(kex_algo)
        languages_stoc = extract_string(i)
        i += len(kex_algo)

        return cls(cookie, kex_algo, server_host_key_algo, encryption_algo_ctos, encryption_algo_stoc,
                   mac_algo_ctos, mac_algo_stoc, compression_algo_ctos, compression_algo_stoc,
                   languages_ctos, languages_stoc)

    def __init__(self, cookie=b"\x02" * 16,
                 kex_algo=b"curve25519-sha256", server_host_key_algo=b"ecdsa-sha2-nistp256-cert-v01@openssh.com",
                 encryption_algo_ctos=b"aes128-ctr", encryption_algo_stoc=b"aes128-ctr",
                 mac_algo_ctos=b"hmac-sha2-512", mac_algo_stoc=b"hmac-sha2-512",
                 compression_algo_ctos=b"none", compression_algo_stoc=b"none",
                 languages_ctos=b"", languages_stoc=b""):
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
        message += len(self.kex_algo).to_bytes(4, 'big') + self.kex_algo
        message += len(self.server_host_key_algo).to_bytes(4, 'big') + self.server_host_key_algo
        message += len(self.encryption_algo_ctos).to_bytes(4, 'big') + self.encryption_algo_ctos
        message += len(self.encryption_algo_stoc).to_bytes(4, 'big') + self.encryption_algo_stoc
        message += len(self.mac_algo_ctos).to_bytes(4, 'big') + self.mac_algo_ctos
        message += len(self.mac_algo_stoc).to_bytes(4, 'big') + self.mac_algo_stoc
        message += len(self.compression_algo_ctos).to_bytes(4, 'big') + self.compression_algo_ctos
        message += len(self.compression_algo_stoc).to_bytes(4, 'big') + self.compression_algo_stoc
        message += len(self.languages_ctos).to_bytes(4, 'big') + self.languages_ctos
        message += len(self.languages_stoc).to_bytes(4, 'big') + self.languages_stoc
        message += b"\x00"  # KEX first packet follows: FALSE
        message += int(0).to_bytes(4, 'big')  # reserved

        return self._to_bytes(message)


with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
    s.connect(("delos.imag.fr", 22))
    print("connexion established")

    s_w = s.makefile(mode="wb")
    s_r = s.makefile(mode="rb")

    print("Sending version")
    s_w.write(b"SSH-2.0-pyhton_tim&henry_1.0\r\n")
    s_w.flush()
    data = s_r.readline()
    print("Found server version: %s" % data.decode("utf-8"))

    message = KeiSshPacket().to_bytes()
    s_w.write(message)
    s_w.flush()
    print("Sent %s" % message)
    data = s_r.read(32)
    data = BinarySshPacket.from_bytes(data)
    print("Found data: %s" % data)
