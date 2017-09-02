import os
from enum import IntEnum


class SshMsgType(IntEnum):
    SSH_MSG_KEXINIT = 0x14
    SSH_MSG_NEWKEYS = 0x15
    SSH_MSG_KEX_ECDH_INIT = 0x1e
    SSH_MSG_KEX_ECDH_REPLY = 0x1f


class BinarySshPacket:
    msg_type = None  # Should be filled by subclasses

    _msg_types = {}

    @classmethod
    def packet_metaclass(cls, name, bases, clsdict):
        the_class = type(name, bases, clsdict)
        cls._msg_types[the_class.msg_type] = the_class
        return the_class

    @classmethod
    def from_bytes(cls, flow):
        # after receiving a generic ssh packet, this function derives the correct subclass.
        packet_len = int.from_bytes(flow[0:4], 'big')
        padding_length = flow[4]
        msg_type = flow[5]
        payload = flow[6:(6 + packet_len - padding_length - 1)]
        _ = flow[(6 + packet_len - padding_length - 1):(6 + packet_len - 1)]  # padding
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
    msg_type = SshMsgType.SSH_MSG_KEXINIT

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

    def __init__(self, cookie=os.urandom(16),
                 kex_algo=("ecdh-sha2-nistp256",), server_host_key_algo=("ssh-rsa",),
                 encryption_algo_ctos=("aes128-ctr",), encryption_algo_stoc=("aes128-ctr",),
                 mac_algo_ctos=("hmac-sha2-256-etm@openssh.com",), mac_algo_stoc=("hmac-sha2-256-etm@openssh.com",),
                 compression_algo_ctos=("none",), compression_algo_stoc=("none",),
                 languages_ctos=(), languages_stoc=()):
        super(KexinitSshPacket, self).__init__()
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


class NewKeysSshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_NEWKEYS

    @classmethod
    def from_bytes(cls, flow):
        return cls()

    def to_bytes(self):
        return self._to_bytes(b"")


class KexSshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_KEX_ECDH_INIT

    def __init__(self, public_key):
        super(KexSshPacket, self).__init__()
        self.e = public_key.public_numbers().encode_point()

    def to_bytes(self):
        message = self._field_to_bytes(self.e)
        return self._to_bytes(message)


class KexdhReplySshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_KEX_ECDH_REPLY

    @classmethod
    def from_bytes(cls, flow):
        # disect payload
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
        self._f = f
        self.f_sig = f_sig

    @property
    def f(self):
        return self._f.to_bytes(65, 'big')

    @f.setter
    def f(self, f):
        if not isinstance(f, int):
            raise Exception("Server's public key must be stored as an integer!")
        else:
            self._f = f
