# Implementation of SSH messages types. See All RFCs 4251, 4252, 4253 for
# their description.

import itertools
from enum import IntEnum, Enum

from fields import *


class SshMsgType(IntEnum):
    # Transport layer protocol
    #   Transport layer generic
    DISCONNECT = 1
    IGNORE = 2
    UNIMPLEMENTED = 3
    DEBUG = 4
    SERVICE_REQUEST = 5
    SERVICE_ACCEPT = 6
    #   Algorithm negotiation
    KEXINIT = 20
    NEWKEYS = 21
    #   Key exchange method specific. FIXME: really set these types there?
    KEX_ECDH_INIT = 30
    KEX_ECDH_REPLY = 31

    # User authentication protocol
    #   User authentication generic
    USERAUTH_REQUEST = 50
    USERAUTH_FAILURE = 51
    USERAUTH_SUCCESS = 52
    USERAUTH_BANNER = 53

    # Connection protocol
    #   Connection protocol generic
    GLOBAL_REQUEST = 80
    REQUEST_SUCCESS = 81
    REQUEST_FAILURE = 82
    #   Channel related messages
    CHANNEL_OPEN = 90
    CHANNEL_OPEN_CONFIRMATION = 91
    CHANNEL_OPEN_FAILURE = 92
    CHANNEL_WINDOW_ADJUST = 93
    CHANNEL_DATA = 94
    CHANNEL_EXTENDED_DATA = 95
    CHANNEL_EOF = 96
    CHANNEL_CLOSE = 97
    CHANNEL_REQUEST = 98
    CHANNEL_SUCCESS = 99
    CHANNEL_FAILURE = 100


class ServiceName(str, Enum):
    USERAUTH = "ssh-userauth"
    CONNECTION = "ssh-connection"


class MethodName(str, Enum):
    NONE = "none"
    PASSWORD = "password"
    PUBLICKEY = "publickey"


class BinarySshPacket(metaclass=abc.ABCMeta):
    known_msg_types = {}

    __slots__ = ('mac', 'message_length', 'padding_length', 'msg_type')

    _field_types = (None,  # Not parsed at all
                    None, None, None)  # Manually parsed fields

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
        flow_iterator = flow.__iter__()

        # Read header
        packet_len = cls.packet_length_type.from_bytes(flow_iterator)
        padding_length = cls.padding_length_type.from_bytes(flow_iterator)
        msg_type = cls.message_type_type.from_bytes(flow_iterator)

        try:
            msg_class = cls.known_msg_types[msg_type]
        except KeyError:
            try:
                raise Exception("Unparsable message %s" % SshMsgType(msg_type).name)
            except ValueError:
                raise Exception("Unknown message type %d" % msg_type)
        else:
            parsed_data = {}
            # Parse fields
            for fname, ftype in zip(
                    itertools.chain.from_iterable(getattr(cls, '__slots__', [])
                                                  for cls in reversed(msg_class.__mro__)),
                    itertools.chain.from_iterable(getattr(cls, '_field_types', [])
                                                  for cls in reversed(msg_class.__mro__))):
                if ftype is not None:
                    parsed_data[fname] = ftype.from_bytes(flow_iterator)

        # Read padding
        for _ in range(padding_length):
            flow_iterator.__next__()

        # Read MAC
        mac = bytes(b for b in flow_iterator)
        # TODO: check the MAC

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
        for fname, ftype in zip(
                itertools.chain.from_iterable(getattr(cls, '__slots__', [])
                                              for cls in reversed(self.__class__.__mro__)),
                itertools.chain.from_iterable(getattr(cls, '_field_types', [])
                                              for cls in reversed(self.__class__.__mro__))):
            if ftype is not None:
                message += ftype.to_bytes(self.__getattribute__(fname))
        return message

    def __repr__(self):
        fields = ("%s=%r" % (fname, self.__getattribute__(fname)) for fname in self.__slots__)
        fields = ', '.join(fields)
        return "%s<%s>" % (self.__class__.__name__, fields)

    def __str__(self):
        return "%s" % self.__class__.__name__


class Disconnect(BinarySshPacket, msg_type=SshMsgType.DISCONNECT):
    class ReasonCode(IntEnum):
        HOST_NOT_ALLOWED_TO_CONNECT = 1
        PROTOCOL_ERROR = 2
        KEY_EXCHANGE_FAILED = 3
        RESERVED = 4
        MAC_ERROR = 5
        COMPRESSION_ERROR = 6
        SERVICE_NOT_AVAILABLE = 7
        PROTOCOL_VERSION_NOT_SUPPORTED = 8
        HOST_KEY_NOT_VERIFIABLE = 9
        CONNECTION_LOST = 10
        BY_APPLICATION = 11
        TOO_MANY_CONNECTIONS = 12
        AUTH_CANCELLED_BY_USER = 13
        NO_MORE_AUTH_METHODS_AVAILABLE = 14
        ILLEGAL_USER_NAME = 15

    __slots__ = ('reason_code', 'description', 'language_tag')
    _field_types = (Uint32Type(), StringType('utf-8'), StringType('octet'))
    # TODO: read RFC 3066 to decode language_tag


class Ignore(BinarySshPacket, msg_type=SshMsgType.IGNORE):
    __slots__ = ('data',)
    _field_types = (None,)


class Unimplemented(BinarySshPacket, msg_type=SshMsgType.UNIMPLEMENTED):
    __slots__ = ('packet_sequence_number',)
    _field_types = (Uint32Type())


class Debug(BinarySshPacket, msg_type=SshMsgType.DEBUG):
    __slots__ = ('always_display', 'message', 'language_tag')
    _field_types = (BooleanType(), StringType('utf-8'), StringType('octet'))
    # TODO: read RFC 3066 to decode language_tag


class ServiceRequest(BinarySshPacket, msg_type=SshMsgType.SERVICE_REQUEST):
    __slots__ = ('service_name',)
    _field_types = (StringType('ascii'),)


class ServiceAccept(BinarySshPacket, msg_type=SshMsgType.SERVICE_ACCEPT):
    __slots__ = ('service_name',)
    _field_types = (StringType('ascii'),)


class KexInit(BinarySshPacket, msg_type=SshMsgType.KEXINIT):
    __slots__ = ('cookie',
                 'kex_algo', 'server_host_key_algo',
                 'encryption_algo_ctos', 'encryption_algo_stoc',
                 'mac_algo_ctos', 'mac_algo_stoc',
                 'compression_algo_ctos', 'compression_algo_stoc',
                 'languages_ctos', 'languages_stoc',
                 'first_kex_packet_follows', '_reserved')

    _field_types = (BytesType(16),
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


class NewKeys(BinarySshPacket, msg_type=SshMsgType.NEWKEYS):
    __slots__ = ()
    _field_types = ()


class KexDHInit(BinarySshPacket, msg_type=SshMsgType.KEX_ECDH_INIT):
    __slots__ = ('e',)
    _field_types = (StringType('octet'),)


class KexDHReply(BinarySshPacket, msg_type=SshMsgType.KEX_ECDH_REPLY):
    __slots__ = ('server_public_key', 'f', 'signature')
    _field_types = (StringType('octet'), StringType('octet'), StringType('octet'))


class UserauthRequest(BinarySshPacket, msg_type=SshMsgType.USERAUTH_REQUEST):
    __slots__ = ('user_name', 'service_name', 'method_name')
    _field_types = (StringType('utf-8'), StringType('ascii'), StringType('ascii'))


class UserauthRequestNone(UserauthRequest):
    __slots__ = ()
    _field_types = ()

    def __init__(self, method_name=None, **kwargs):
        if method_name is not None and method_name != MethodName.NONE:
            raise Exception("%s only supports \"%s\" method" % (self.__class__.__name__, MethodName.NONE.name))
        super().__init__(method_name=MethodName.NONE, **kwargs)


class UserauthRequestPassword(UserauthRequest):
    __slots__ = ('change_password', 'password')
    _field_types = (BooleanType(), StringType('utf-8'))

    def __init__(self, method_name, change_password, **kwargs):
        if method_name is not None and method_name != "password":
            raise Exception("%s only supports \"password\" method" % self.__class__.__name__)
        if change_password:
            raise Exception("Changing password is currently not supported")
        super().__init__(method_name="password", change_password=False, **kwargs)


class UserauthFailure(BinarySshPacket, msg_type=SshMsgType.USERAUTH_FAILURE):
    __slots__ = ('authentications_that_can_continue', 'partial_success')
    _field_types = (NameListType(), BooleanType())


class UserauthSuccess(BinarySshPacket, msg_type=SshMsgType.USERAUTH_SUCCESS):
    __slots__ = ()
    _field_types = ()


class UserauthBanner(BinarySshPacket, msg_type=SshMsgType.USERAUTH_BANNER):
    __slots__ = ('message', 'language_tag')
    _field_types = (StringType('utf-8'), StringType('octet'))  # TODO: read RFC 3066 to decode language_tag


class GlobalRequest(BinarySshPacket, msg_type=SshMsgType.GLOBAL_REQUEST):
    __slots__ = ('request_name', 'want_reply')
    _field_types = (StringType('ascii'), BooleanType())


class RequestSuccess(BinarySshPacket, msg_type=SshMsgType.REQUEST_SUCCESS):
    __slots__ = ()
    _field_types = ()


class RequestFailure(BinarySshPacket, msg_type=SshMsgType.REQUEST_FAILURE):
    __slots__ = ()
    _field_types = ()


class ChannelOpen(BinarySshPacket, msg_type=SshMsgType.CHANNEL_OPEN):
    __slots__ = ('channel_type', 'sender_channel', 'initial_window_size', 'maximum_packet_size')
    _field_types = (StringType('ascii'), Uint32Type(), Uint32Type(), Uint32Type())


class ChannelOpenConfimation(BinarySshPacket, msg_type=SshMsgType.CHANNEL_OPEN_CONFIRMATION):
    __slots__ = ('recipient_channel', 'sender_channel', 'initial_window_size', 'maximum_packet_size')
    _field_types = (Uint32Type(), Uint32Type(), Uint32Type(), Uint32Type())


class ChannelOpenFailure(BinarySshPacket, msg_type=SshMsgType.CHANNEL_OPEN_FAILURE):
    class ReasonCode(int, Enum):
        ADMINISTRATIVELY_PROHIBITED = 1
        CONNECT_FAILED = 2
        UNKNOWN_CHANNEL_TYPE = 3
        RESOURCE_SHORTAGE = 4

    __slots__ = ('recipient_channel', 'reason_code', 'description', 'language_tag')
    _field_types = (Uint32Type(), Uint32Type(), StringType('utf-8'), StringType('octet'))


class ChannelWindowAdjust(BinarySshPacket, msg_type=SshMsgType.CHANNEL_WINDOW_ADJUST):
    __slots__ = ('recipient_channel', 'bytes_to_add')
    _field_types = (Uint32Type(), Uint32Type())


class ChannelExtendedData(BinarySshPacket, msg_type=SshMsgType.CHANNEL_EXTENDED_DATA):
    class DataTypeCode(int, Enum):
        STDERR = 1

    __slots__ = ('recipient_channel', 'data_type_code', 'data')
    _field_types = (Uint32Type(), Uint32Type(), StringType('octet'))


class ChannelRequest(BinarySshPacket, msg_type=SshMsgType.CHANNEL_REQUEST):
    __slots__ = ('recipient_channel', 'request_type', 'want_reply')
    _field_types = (Uint32Type(), StringType('ascii'), BooleanType())


class ChannelRequestPTY(ChannelRequest):
    class EncodedTerminalModes(int, Enum):
        TTY_OP_END = 0,  # Indicates end of options.
        VINTR = 1,  # Interrupt character; 255 if none.  Similarly for the
        # other characters.  Not all of these characters are supported on
        # all systems.
        VQUIT = 2,  # The quit character (sends SIGQUIT signal on POSIX systems).
        VERASE = 3,  # Erase the character to left of the cursor.
        VKILL = 4,  # Kill the current input line.
        VEOF = 5,  # End-of-file character (sends EOF from the terminal).
        VEOL = 6,  # End-of-line character in addition to carriage return and/or linefeed.
        VEOL2 = 7,  # Additional end-of-line character.
        VSTART = 8,  # Continues paused output (normally control-Q).
        VSTOP = 9,  # Pauses output (normally control-S).
        VSUSP = 10,  # Suspends the current program.
        VDSUSP = 11,  # Another suspend character.
        VREPRINT = 12,  # Reprints the current input line.
        VWERASE = 13,  # Erases a word left of cursor.
        VLNEXT = 14,  # Enter the next character typed literally, even if it is a special character
        VFLUSH = 15,  # Character to flush output.
        VSWTCH = 16,  # Switch to a different shell layer.
        VSTATUS = 17,  # Prints system status line (load, command, pid, etc).
        VDISCARD = 18,  # Toggles the flushing of terminal output.
        IGNPAR = 30,  # The ignore parity flag.  The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE.
        PARMRK = 31,  # Mark parity and framing errors.
        INPCK = 32,  # Enable checking of parity errors.
        ISTRIP = 33,  # Strip 8th bit off characters.
        INLCR = 34,  # Map NL into CR on input.
        IGNCR = 35,  # Ignore CR on input.
        ICRNL = 36,  # Map CR to NL on input.
        IUCLC = 37,  # Translate uppercase characters to lowercase.
        IXON = 38,  # Enable output flow control.
        IXANY = 39,  # Any char will restart after stop.
        IXOFF = 40,  # Enable input flow control.
        IMAXBEL = 41,  # Ring bell on input queue full.
        ISIG = 50,  # Enable signals INTR, QUIT, [D]SUSP.
        ICANON = 51,  # Canonicalize input lines.
        XCASE = 52,  # Enable input and output of uppercase characters by
        # preceding their lowercase equivalents with "\".
        ECHO = 53,  # Enable echoing.
        ECHOE = 54,  # Visually erase chars.
        ECHOK = 55,  # Kill character discards current line.
        ECHONL = 56,  # Echo NL even if ECHO is off.
        NOFLSH = 57,  # Don't flush after interrupt.
        TOSTOP = 58,  # Stop background jobs from output.
        IEXTEN = 59,  # Enable extensions.
        ECHOCTL = 60,  # Echo control characters as ^(Char).
        ECHOKE = 61,  # Visual erase for line kill.
        PENDIN = 62,  # Retype pending input.
        OPOST = 70,  # Enable output processing.
        OLCUC = 71,  # Convert lowercase to uppercase.
        ONLCR = 72,  # Map NL to CR-NL.
        OCRNL = 73,  # Translate carriage return to newline (output).
        ONOCR = 74,  # Translate newline to carriage return-newline (output).
        ONLRET = 75,  # Newline performs a carriage return (output).
        CS7 = 90,  # 7 bit mode.
        CS8 = 91,  # 8 bit mode.
        PARENB = 92,  # Parity enable.
        PARODD = 93,  # Odd parity, else even.
        TTY_OP_ISPEED = 128,  # Specifies the input baud rate in bits per second.
        TTY_OP_OSPEED = 129,  # Specifies the output baud rate in bits per second.

    class EncodedTerminalModeType(StringType):
        def __init__(self):
            super().__init__('octet')

        def from_bytes(self, flow):
            options = []
            while True:
                # > The stream consists of opcode-argument pairs wherein the
                # > opcode is a byte value.
                op_code, argument = flow.__next__(), None
                # > The stream is terminated by opcode TTY_OP_END (0x00).
                if op_code == ChannelRequestPTY.EncodedTerminalModes.TTY_OP_END:
                    break
                # > Opcodes 160 to 255 are not yet defined, and cause parsing to stop
                elif 160 <= op_code <= 255:
                    self.logger.warning("Detected undefined opcode %d, stop parsing" % op_code)
                    break
                # > Opcodes 1 to 159 have a single uint32 argument.
                elif 1 <= op_code <= 159:
                    argument = bytes(flow.__next__() for _ in range(4))
                options.append((op_code, argument))
            return options

        def to_bytes(self, value):
            flow = bytearray()
            for op_code, argument in value:
                flow.append(op_code)
                flow += argument.to_bytes(4, NETWORK_BYTE_ORDER)
            flow.append(ChannelRequestPTY.EncodedTerminalModes.TTY_OP_END)
            return super().to_bytes(flow)

    __slots__ = ('TERM',
                 'terminal_width_ch', 'terminal_height_ch',
                 'terminal_width_px', 'terminal_height_px',
                 'encoded_terminal_modes')
    _field_types = (StringType('ascii'),
                    Uint32Type(), Uint32Type(),
                    Uint32Type(), Uint32Type(),
                    EncodedTerminalModeType())

    def __init__(self, request_type=None, **kwargs):
        if request_type is not None and request_type != 'pty-req':
            raise Exception("%s only supports \"pty-req\" request type" % self.__class__.__name__)
        super().__init__(request_type='pty-req', **kwargs)


class ChannelRequestShell(ChannelRequest):
    __slots__ = ()
    _field_types = ()

    def __init__(self, request_type=None, **kwargs):
        if request_type is not None and request_type != 'shell':
            raise Exception("%s only supports \"shell\" request type" % self.__class__.__name__)
        super().__init__(request_type='shell', **kwargs)
