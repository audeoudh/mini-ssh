import abc
import os
from enum import IntEnum
from typing import Union


class SshMsgType(IntEnum):
    SSH_MSG_KEXINIT = 20
    SSH_MSG_NEWKEYS = 21

    SSH_MSG_KEX_ECDH_INIT = 30
    SSH_MSG_KEX_ECDH_REPLY = 31

    SSH_MSG_USERAUTH_REQUEST = 50
    SSH_MSG_USERAUTH_FAILURE = 51
    SSH_MSG_USERAUTH_SUCCESS = 52
    SSH_MSG_USERAUTH_BANNER = 53


class BinarySshPacket(metaclass=abc.ABCMeta):
    msg_type = None  # Should be filled by subclasses

    _msg_types = {}

    @classmethod
    def packet_metaclass(cls, name, bases, clsdict):
        the_class = type(name, bases, clsdict)
        cls._msg_types[the_class.msg_type] = the_class
        return the_class

    @classmethod
    def _byte_from_bytes(cls, flow) -> (int, int):
        return 1, flow[0]

    @classmethod
    def _byte_to_bytes(cls, value: int):
        return value.to_bytes(1, 'big')

    @classmethod
    def _bool_from_bytes(cls, flow) -> (int, bool):
        return 1, flow[0] != 0

    @classmethod
    def _bool_to_bytes(cls, value: bool):
        if value:
            return b"\x01"
        else:
            return b"\x00"

    @classmethod
    def _uint32_from_bytes(cls, flow) -> (int, int):
        return 4, int.from_bytes(flow[0:4], 'big', signed=False)

    @classmethod
    def _uint32_to_bytes(cls, value: int):
        return value.to_bytes(4, 'big', signed=False)

    @classmethod
    def _uint64_from_bytes(cls, flow) -> (int, int):
        return 8, int.from_bytes(flow[0:8], 'big', signed=False)

    @classmethod
    def _uint64_to_bytes(cls, value: int):
        return value.to_bytes(8, 'big', signed=False)

    @classmethod
    def _string_from_bytes(cls, flow, encoding="ascii") -> (int, Union[str, bytes]):
        """If encoding is "octet", read a raw octet-string and return a bytes object. Or,
        decode it according to the encoding"""
        read_len, string_size = cls._uint32_from_bytes(flow)
        string = flow[read_len:(read_len + string_size)]
        if encoding != "octet":
            string = string.decode(encoding)
        read_len += string_size
        return read_len, string

    @classmethod
    def _string_to_bytes(cls, value: Union[str, bytes], encoding="ascii"):
        length = cls._uint32_to_bytes(len(value))
        string = value
        if encoding != "octet":
            string = value.encode(encoding)
        return length + string

    @classmethod
    def _mpint_from_bytes(cls, flow) -> (int, int):
        read_len, mpi_len = cls._uint32_from_bytes(flow)
        mpi = int.from_bytes(flow[read_len:(read_len + mpi_len)], 'big')
        read_len += mpi_len
        return read_len, mpi

    @classmethod
    def _mpint_to_bytes(cls, value: int, mpi_len: int = None):
        if mpi_len is None:
            mpi_len = (value.bit_length() + 7) // 8
        length = cls._uint32_to_bytes(mpi_len)
        mpi = value.to_bytes(mpi_len, 'big')
        return length + mpi

    @classmethod
    def _list_from_bytes(cls, flow) -> (int, list):
        read_len, list_len = cls._uint32_from_bytes(flow)
        list_ = flow[read_len:(read_len + list_len)].decode("ascii").split(",")
        read_len += list_len
        return read_len, list_

    @classmethod
    def _list_to_bytes(cls, value: list):
        list_ = ",".join(value).encode("ascii")
        length = cls._uint32_to_bytes(len(list_))
        return length + list_

    @classmethod
    def from_bytes(cls, flow):
        i = 0
        read_len, packet_len = cls._uint32_from_bytes(flow[i:])
        i += read_len
        read_len, padding_length = cls._byte_from_bytes(flow[i:])
        i += read_len
        read_len, msg_type = cls._byte_from_bytes(flow[i:])
        i += read_len
        payload = flow[i:(i + packet_len - padding_length - 1)]
        i += len(payload)
        i += padding_length
        mac = flow[(i + packet_len - 1):]

        return cls._msg_types[msg_type].from_bytes(payload)

    def to_bytes(self, mac_creator=None, cipher_block_size=8):
        """Convert the packet to byte flow.

        cipher_block_size: the size of a cipher block.
        mac_creator: a function that computes the mac for the given
          payload"""
        payload = self._payload()

        # Prepend message type
        payload = self._byte_to_bytes(self.msg_type) + payload

        # Padding
        cipher_block_size = max(cipher_block_size, 8)
        pckt_len = 4 + 1 + len(payload)
        if pckt_len < max(16, cipher_block_size):
            pad_len = max(16, cipher_block_size) - pckt_len
        else:
            pad_len = cipher_block_size - pckt_len % cipher_block_size
        if pad_len < 4:
            pad_len += cipher_block_size
        packet = self._byte_to_bytes(pad_len) + payload + b"\00" * pad_len

        # Packet length
        packet = self._uint32_to_bytes(len(packet)) + packet

        # MAC field
        if mac_creator is not None:
            mac = mac_creator(packet)
            packet += mac

        return packet

    def _payload(self):
        """Convert all the fields of the concrete message to a flow of bytes."""
        # Do not use abstract here, as some message cannot be sent from the client, so they do not have a `_payload`
        # method, but are, in fact, concrete
        return NotImplementedError()


class KexinitSshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_KEXINIT

    @classmethod
    def from_bytes(cls, flow):
        cookie = flow[0:16]
        i = 16
        read_len, kex_algo = cls._list_from_bytes(flow[i:])
        i += read_len
        read_len, server_host_key_algo = cls._list_from_bytes(flow[i:])
        i += read_len
        read_len, encryption_algo_ctos = cls._list_from_bytes(flow[i:])
        i += read_len
        read_len, encryption_algo_stoc = cls._list_from_bytes(flow[i:])
        i += read_len
        read_len, mac_algo_ctos = cls._list_from_bytes(flow[i:])
        i += read_len
        read_len, mac_algo_stoc = cls._list_from_bytes(flow[i:])
        i += read_len
        read_len, compression_algo_ctos = cls._list_from_bytes(flow[i:])
        i += read_len
        read_len, compression_algo_stoc = cls._list_from_bytes(flow[i:])
        i += read_len
        read_len, languages_ctos = cls._list_from_bytes(flow[i:])
        i += read_len
        read_len, languages_stoc = cls._list_from_bytes(flow[i:])
        i += read_len
        _, first_kex_packet_follows = cls._bool_from_bytes(flow[i:])

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

    def _payload(self):
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
        message += self._bool_to_bytes(False)  # KEX first packet follows
        message += self._uint32_to_bytes(0)  # reserved

        return message


class NewKeysSshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_NEWKEYS

    @classmethod
    def from_bytes(cls, flow):
        return cls()

    def _payload(self):
        return b""


class KexSshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_KEX_ECDH_INIT

    def __init__(self, public_key):
        super(KexSshPacket, self).__init__()
        self.e = public_key.public_numbers().encode_point()

    def _payload(self):
        message = self._string_to_bytes(self.e, encoding="octet")
        return message


class KexdhReplySshPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_KEX_ECDH_REPLY

    @classmethod
    def from_bytes(cls, flow):
        # disect payload
        i = 0
        read_len, server_key = cls._string_from_bytes(flow[i:], encoding="octet")
        i += read_len
        read_len, f = cls._mpint_from_bytes(flow[i:])
        i += read_len
        _, f_sig = cls._string_from_bytes(flow[i:], encoding="octet")
        return cls(server_key, f, f_sig)

    def __init__(self, server_key, f, f_sig):
        super(KexdhReplySshPacket, self).__init__()
        self.server_key = server_key
        self.f = f
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


class UserauthRequestPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_USERAUTH_REQUEST

    def __init__(self, user_name, service_name, method_name):
        self.user_name = user_name
        self.service_name = service_name
        self.method_name = method_name

    def _payload(self):
        message = self._string_to_bytes(self.user_name, encoding="utf-8")
        message += self._string_to_bytes(self.service_name, encoding="ascii")
        message += self._string_to_bytes(self.method_name, encoding="ascii")
        return message


class UserauthFailurePacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_USERAUTH_FAILURE

    def __init__(self, next_authentications, partial_success):
        self.next_authentications = next_authentications
        self.partial_success = partial_success

    @classmethod
    def from_bytes(cls, flow):
        i = 0
        read_len, next_authentications = cls._list_from_bytes(flow[i:])
        i += read_len
        _, partial_success = cls._bool_from_bytes(flow[i:])
        return cls(next_authentications, partial_success)


class UserauthSuccessPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_USERAUTH_SUCCESS

    @classmethod
    def from_bytes(cls, flow):
        return cls()


class UserauthPublickeyRequestPacket(UserauthRequestPacket, metaclass=BinarySshPacket.packet_metaclass):
    def __init__(self, user_name, service_name, algo_name, blob):
        super().__init__(user_name, service_name, "publickey")
        self.algo_name = algo_name
        self.blob = blob

    def _payload(self, private_key=None):
        """Provide a private key and the message will be signed"""
        message = super().to_bytes()
        message += self._bool_to_bytes(private_key is not None)
        message += self._string_to_bytes(self.algo_name, encoding="ascii")

        # Blob. Extract data according to the algo name
        if self.algo_name == "ssh-rsa":
            e, n = self.blob
            message += self._mpint_to_bytes(e)
            message += self._mpint_to_bytes(n)
        else:
            # Don't know this algorithm. Use the blob as is and hope all is normal
            message += self._string_to_bytes(self.blob, encoding="octet")

        # Add signature
        if private_key is not None:
            to_be_signed = self._string_to_bytes(b"", encoding="octet")
            to_be_signed += message
            signature = private_key.sign(to_be_signed)
            message += self._string_to_bytes(signature, encoding="octet")

        return message


class UserauthBannerPacket(BinarySshPacket, metaclass=BinarySshPacket.packet_metaclass):
    msg_type = SshMsgType.SSH_MSG_USERAUTH_BANNER

    def __init__(self, message, language_tag):
        self.message = message
        self.language_tag = language_tag

    @classmethod
    def from_bytes(cls, flow):
        i = 0
        read_len, message = cls._string_from_bytes(flow[i:], encoding="utf-8")
        i += read_len
        language_tag = flow[i:]  # TODO: read RFC 3066 and decode this field
        return cls(message, language_tag)
