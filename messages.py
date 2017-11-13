# Implementation of SSH messages types. See All RFCs 4251, 4252, 4253 for
# their description.

from enum import IntEnum

from fields import *


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
    known_msg_types = {}

    __slots__ = ('mac', 'msg_type')

    _fields_type = (None, ByteType)

    packet_length_type = Uint32Type()
    padding_length_type = ByteType()
    message_type_type = ByteType()

    def __init_subclass__(cls, msg_type=None, **kwargs):
        """Initialize the subclass when it is created.

        :param int msg_type: The type of the message. Have to be known to
        automatically parse the correct message type in the `from_bytes` class
        method. If None, the subclass won't be registered and the parsing
        mechanism won't ever return a message of this type."""
        super().__init_subclass__(**kwargs)
        if msg_type is not None:
            cls.msg_type = msg_type
            cls.known_msg_types[msg_type] = cls

    def __init__(self, **kwargs):
        """Initializer.

        Arguments are a mapping of attribute names / values."""
        super().__init__()
        for attr_name, attr_value in kwargs.items():
            self.__setattr__(attr_name, attr_value)

    @classmethod
    def from_bytes(cls, flow):
        i = 0
        read_len, packet_len = cls.packet_length_type.from_bytes(flow[i:])
        i += read_len
        read_len, padding_length = cls.padding_length_type.from_bytes(flow[i:])
        i += read_len
        read_len, msg_type = cls.message_type_type.from_bytes(flow[i:])
        i += read_len
        payload = flow[i:(i + packet_len - padding_length - 2)]
        i += len(payload)
        i += padding_length
        mac = flow[(i + packet_len - 1):]

        try:
            msg_class = cls.known_msg_types[msg_type]
        except KeyError:
            raise Exception("Unknown message type %d" % msg_type)
        else:
            parsed_data = {}
            i = 0
            # Parse fields
            for fname, ftype in zip(msg_class.__slots__, msg_class._fields_type):
                read_len, parsed_data[fname] = ftype.from_bytes(payload[i:])
                i += read_len
            # Build the message
            return msg_class(**parsed_data)

    def to_bytes(self, cipher_block_size=8):
        """Convert the packet to byte flow.

        This method does not handle MAC and encryption. For this,
        consider using the `transport` module.

        cipher_block_size: Size of a cipher block. Use 1 for stream
          ciphers"""
        payload_bytes = self.payload()

        # Prepend message type
        payload = self.message_type_type.to_bytes(self.msg_type) + payload_bytes

        # Padding
        cipher_block_size = max(cipher_block_size, 8)
        pckt_len = 4 + 1 + len(payload)
        if pckt_len < max(16, cipher_block_size):
            pad_len = max(16, cipher_block_size) - pckt_len
        else:
            pad_len = cipher_block_size - pckt_len % cipher_block_size
        if pad_len < 4:
            pad_len += cipher_block_size
        packet = self.padding_length_type.to_bytes(pad_len) + payload + b"\00" * pad_len

        # Packet length
        packet = self.packet_length_type.to_bytes(len(packet)) + packet

        return packet

    def payload(self):
        """Convert the packet to a byte flow.

        Contrary to `to_bytes`, this method only produces bytes for the
        payload part of the SSH packet: no length, no padding, no mac…
        """
        message = b""
        for fname, ftype in zip(self.__slots__, self._fields_type):
            message += ftype.to_bytes(self.__getattribute__(fname))
        return message

    def __str__(self):
        fields = ("%s=%r" % (fname, self.__getattribute__(fname)) for fname in self.__slots__)
        fields = ', '.join(fields)
        return "%s<%s>" % (self.__class__.__name__, fields)


class KexInit(BinarySshPacket, msg_type=SshMsgType.SSH_MSG_KEXINIT):
    __slots__ = ('cookie',
                 'kex_algo', 'server_host_key_algo',
                 'encryption_algo_ctos', 'encryption_algo_stoc',
                 'mac_algo_ctos', 'mac_algo_stoc',
                 'compression_algo_ctos', 'compression_algo_stoc',
                 'languages_ctos', 'languages_stoc',
                 'first_kex_packet_follows', '_reserved')

    _fields_type = (BytesType(16),
                    NameListType(), NameListType(),
                    NameListType(), NameListType(),
                    NameListType(), NameListType(),
                    NameListType(), NameListType(),
                    NameListType(), NameListType(),
                    BooleanType(), Uint32Type())

    # Specific default value
    def __init__(self, _reserved=0, **kwargs):
        super(KexInit, self).__init__(**kwargs)
        self._reserved = _reserved


class NewKeys(BinarySshPacket, msg_type=SshMsgType.SSH_MSG_NEWKEYS):
    __slots__ = ()
    _fields_type = ()


class KexDHInit(BinarySshPacket, msg_type=SshMsgType.SSH_MSG_KEX_ECDH_INIT):
    __slots__ = ('e',)
    _fields_type = (StringType('octet'),)


class KexDHReply(BinarySshPacket, msg_type=SshMsgType.SSH_MSG_KEX_ECDH_REPLY):
    __slots__ = ('server_public_key', 'f', 'signature')
    _fields_type = (StringType('octet'), StringType('octet'), StringType('octet'))


class UserauthRequest(BinarySshPacket, msg_type=SshMsgType.SSH_MSG_USERAUTH_REQUEST):
    __slots__ = ('user_name', 'service_name', 'method_name')
    _fields_type = (StringType('utf-8'), StringType('ascii'), StringType('ascii'))


class UserauthPublickeyRequestPacket(UserauthRequest):
    # FIXME: does inheritance really works?
    __slots__ = ('is_actual_authentication', 'public_key_algorithm_name', 'public_key_blob')
    _fields_type = (BooleanType(), StringType('ascii'), StringType('octet'))

    def __init__(self, user_name, service_name, is_actual_authentication, public_key_algorithm_name, public_key_blob):
        super().__init__(user_name=user_name, service_name=service_name, method_name="publickey")
        self.is_actual_authentication = is_actual_authentication
        self.public_key_algorithm_name = public_key_algorithm_name
        self.public_key_blob = public_key_blob

    def payload(self, private_key=None):
        """Provide a private key and the message will be signed"""
        message = super().payload()
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


class UserauthFailure(BinarySshPacket, msg_type=SshMsgType.SSH_MSG_USERAUTH_FAILURE):
    __slots__ = ('authentications_that_can_continue', 'partial_success')
    _fields_type = (NameListType(), BooleanType())


class UserauthSuccess(BinarySshPacket, msg_type=SshMsgType.SSH_MSG_USERAUTH_SUCCESS):
    __slots__ = ()
    _fields_type = ()


class UserauthBanner(BinarySshPacket, msg_type=SshMsgType.SSH_MSG_USERAUTH_BANNER):
    __slots__ = ('message', 'language_tag')
    _fields_type = (StringType('utf-8'), StringType('octet'))  # TODO: read RFC 3066 to decode language_tag
