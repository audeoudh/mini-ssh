import abc
import itertools
from enum import Enum


class Field:
    @classmethod
    @abc.abstractmethod
    def parse(cls, flow): ...


class Byte(int, Field):
    @classmethod
    def parse(cls, flow):
        return cls(flow.__next__())


class Cookie(bytes, Field):
    field_length = 16

    @classmethod
    def parse(cls, flow):
        return cls(flow.__next__() for _ in range(cls.field_length))


class Boolean(Field):  # bool is not subclassable (https://stackoverflow.com/a/2172204/4636017)
    def __init__(self, truthiness):
        self.truthiness = truthiness

    @classmethod
    def parse(cls, flow):
        return cls(flow.__next__() != 0)

    def __bool__(self):
        return self.truthiness


class Uint32(int, Field):
    @classmethod
    def parse(cls, flow):
        value = int.from_bytes((flow.__next__() for _ in range(4)), 'big')
        return cls(value)


class BaseString(Field, metaclass=abc.ABCMeta):
    encoding = None  # May be overwritten in subclasses

    @classmethod
    def parse(cls, flow):
        length = int.from_bytes((flow.__next__() for _ in range(4)), 'big')
        content = bytes(flow.__next__() for _ in range(length))
        if cls.encoding is not None:
            content = content.decode(cls.encoding)
        return cls(content)


class ByteString(bytes, BaseString):
    encoding = None


class AsciiString(str, BaseString):
    encoding = 'ascii'


class Utf8String(str, BaseString):
    encoding = 'utf-8'


class NameList(list, Field):
    @classmethod
    def parse(cls, flow):
        length = int.from_bytes((flow.__next__() for _ in range(4)), 'big')
        content = bytes(flow.__next__() for _ in range(length))
        content = content.decode('ascii')
        content = content.split(',')
        return cls(content)


class SshDataStream(metaclass=abc.ABCMeta):
    __slots__ = ()
    _field_types = ()

    @classmethod
    def field_types(cls):
        yield from zip(
            itertools.chain(getattr(cls, '__slots__', []) for cls in reversed(cls.__mro__)),
            itertools.chain(getattr(cls, '_field_types', []) for cls in reversed(cls.__mro__)))

    @classmethod
    def parse_fields(cls, flow):
        parsed_data = {}
        for fname, ftype in zip(
                getattr(cls, '__slots__', []),
                getattr(cls, '_field_types', [])):
            if ftype is not None:
                parsed_data[fname] = ftype.parse(flow)
        return parsed_data

    def __init__(self, **kwargs):
        for fname, ftype in self.field_types():
            try:
                value = kwargs.pop(fname)
            except KeyError:
                raise Exception("Field %s not provided" % fname)
            else:
                if not isinstance(value, ftype):
                    value = ftype(value)
                setattr(self, fname, value)
        if len(kwargs) != 0:
            fname = next(iter(kwargs))  # Arbitrary element
            raise Exception("Unknown field %s for class %s" % (fname, self.__class__.__name__))


class SshMessage(SshDataStream):
    class MessageType(Byte, Enum):
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

    __slots__ = ('msg_type',)
    _field_types = (MessageType,)

    _subclasses = {}
    _required_attrs = {}

    @classmethod
    def required_attrs(cls):
        zip(
            itertools.chain(getattr(cls, '_required_attrs', {}).items() for cl in reversed(cls.__mro__)),)

    @classmethod
    def __init_subclass__(cls, **kwargs):
        parent_class = cls.__bases__[0]  # Multiple inheritance not supported
        parent_class.subclasses.append(cls)
        cls._subclasses = []
        cls._required_attrs = kwargs

    @classmethod
    def parse(cls, flow):
        if isinstance(flow, (bytes, bytearray)):
            flow = iter(flow)
        msg_class = SshMessage
        data = {}
        while True:
            data.update(msg_class.parse_fields(flow))
            for sc in msg_class._subclasses:
                if all(data.get(k, None) == v for k, v in sc._required_attrs.items()):
                    # This class matches
                    msg_class = sc
                    break
            else:
                # This is the last known class matching this message
                return msg_class(**data)

    def __init__(self, **kwargs):
        for fname, required_value in self._required_attrs:
            try:
                forced_value = kwargs[fname]
            except KeyError:
                # No forced value, ok. Set the value
                kwargs[fname] = required_value
            else:
                if forced_value != required_value:
                    raise Exception("Class %s must have %s=%r" %
                                    (self.__class__.__name__, fname, required_value))
        super().__init__(**kwargs)

    def __repr__(self):
        fields = []
        for cls in reversed(self.__class__.__mro__):
            if cls in (object, SshMessage):
                # Skip the fields of these classes
                continue
            for fname in getattr(cls, '__slots__', []):
                fields.append("%s=%r" % (fname, self.__getattribute__(fname)))
        return "%s<%s>" % (self.__class__.__name__, ', '.join(fields))

    def __str__(self):
        return "%s" % self.__class__.__name__


class Disconnect(SshMessage, msg_type=SshMessage.MessageType.DISCONNECT):
    class ReasonCode(Uint32, Enum):
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
    _field_types = (ReasonCode, Utf8String, ByteString)
    # TODO: read RFC 3066 to decode language_tag


class Ignore(SshMessage, msg_type=SshMessage.MessageType.IGNORE):
    __slots__ = ('data',)
    _field_types = (None,)


class Unimplemented(SshMessage, msg_type=SshMessage.MessageType.UNIMPLEMENTED):
    __slots__ = ('packet_sequence_number',)
    _field_types = (Uint32,)


class Debug(SshMessage, msg_type=SshMessage.MessageType.DEBUG):
    __slots__ = ('always_display', 'message', 'language_tag')
    _field_types = (Boolean, Utf8String, ByteString)
    # TODO: read RFC 3066 to decode language_tag


class ServiceRequest(SshMessage, msg_type=SshMessage.MessageType.SERVICE_REQUEST):
    class ServiceName(AsciiString, Enum):
        USERAUTH = "ssh-userauth"
        CONNECTION = "ssh-connection"

    __slots__ = ('service_name',)
    _field_types = (ServiceName,)


class ServiceAccept(SshMessage, msg_type=SshMessage.MessageType.SERVICE_ACCEPT):
    __slots__ = ('service_name',)
    _field_types = (ServiceRequest.ServiceName,)


class KexInit(SshMessage, msg_type=SshMessage.MessageType.KEXINIT):
    __slots__ = ('cookie',
                 'kex_algo', 'server_host_key_algo',
                 'encryption_algo_ctos', 'encryption_algo_stoc',
                 'mac_algo_ctos', 'mac_algo_stoc',
                 'compression_algo_ctos', 'compression_algo_stoc',
                 'languages_ctos', 'languages_stoc',
                 'first_kex_packet_follows', '_reserved')
    _field_types = (Cookie,
                    NameList, NameList,
                    NameList, NameList,
                    NameList, NameList,
                    NameList, NameList,
                    NameList, NameList,
                    Boolean, Uint32)

    # Specific default value, hidden to the class' user
    def __init__(self, _reserved=0, **kwargs):
        super(KexInit, self).__init__(**kwargs)
        self._reserved = _reserved


class NewKeys(SshMessage, msg_type=SshMessage.MessageType.NEWKEYS):
    __slots__ = ()
    _field_types = ()


class KexDHInit(SshMessage, msg_type=SshMessage.MessageType.KEX_ECDH_INIT):
    __slots__ = ('e',)
    _field_types = (ByteString,)


class KexDHReply(SshMessage, msg_type=SshMessage.MessageType.KEX_ECDH_REPLY):
    __slots__ = ('server_public_key', 'f', 'signature')
    _field_types = (ByteString, ByteString, ByteString)


class UserauthRequest(SshMessage, msg_type=SshMessage.MessageType.USERAUTH_REQUEST):
    class MethodName(AsciiString, Enum):
        NONE = 'none'
        PASSWORD = 'password'
        PUBLICKEY = 'publickey'

    __slots__ = ('user_name', 'service_name', 'method_name')
    _field_types = (Utf8String, AsciiString, MethodName)


class UserauthRequestNone(UserauthRequest, method_name=UserauthRequest.MethodName.NONE):
    __slots__ = ()
    _field_types = ()


class UserauthRequestPassword(UserauthRequest, method_name=UserauthRequest.MethodName.PASSWORD,
                              change_password=False):  # change_password=True currently not supported
    __slots__ = ('change_password', 'password')
    _field_types = (Boolean, Utf8String)

    # Special case: do not display password!
    def __repr__(self):
        fields = []
        for cls in reversed(self.__class__.__mro__):
            if cls in (object, SshMessage):
                # Skip the fields of these classes
                continue
            for fname in getattr(cls, '__slots__', []):
                fvalue = "*" * 8 if fname == 'password' else self.__getattribute__(fname)
                fields.append("%s=%r" % (fname, fvalue))
        return "%s<%s>" % (self.__class__.__name__, ', '.join(fields))


class UserauthFailure(SshMessage, msg_type=SshMessage.MessageType.USERAUTH_FAILURE):
    __slots__ = ('authentications_that_can_continue', 'partial_success')
    _field_types = (NameList, Boolean)


class UserauthSuccess(SshMessage, msg_type=SshMessage.MessageType.USERAUTH_SUCCESS):
    __slots__ = ()
    _field_types = ()


class UserauthBanner(SshMessage, msg_type=SshMessage.MessageType.USERAUTH_BANNER):
    __slots__ = ('message', 'language_tag')
    _field_types = (Utf8String, ByteString)  # TODO: read RFC 3066 to decode language_tag


class GlobalRequest(SshMessage, msg_type=SshMessage.MessageType.GLOBAL_REQUEST):
    __slots__ = ('request_name', 'want_reply')
    _field_types = (AsciiString, Boolean)


class RequestSuccess(SshMessage, msg_type=SshMessage.MessageType.REQUEST_SUCCESS):
    __slots__ = ()
    _field_types = ()


class RequestFailure(SshMessage, msg_type=SshMessage.MessageType.REQUEST_FAILURE):
    __slots__ = ()
    _field_types = ()


class ChannelOpen(SshMessage, msg_type=SshMessage.MessageType.CHANNEL_OPEN):
    __slots__ = ('channel_type', 'sender_channel', 'initial_window_size', 'maximum_packet_size')
    _field_types = (AsciiString, Uint32, Uint32, Uint32)


class ChannelOpenConfimation(SshMessage, msg_type=SshMessage.MessageType.CHANNEL_OPEN_CONFIRMATION):
    __slots__ = ('recipient_channel', 'sender_channel', 'initial_window_size', 'maximum_packet_size')
    _field_types = (Uint32, Uint32, Uint32, Uint32)


class ChannelOpenFailure(SshMessage, msg_type=SshMessage.MessageType.CHANNEL_OPEN_FAILURE):
    class ReasonCode(Uint32, Enum):
        ADMINISTRATIVELY_PROHIBITED = 1
        CONNECT_FAILED = 2
        UNKNOWN_CHANNEL_TYPE = 3
        RESOURCE_SHORTAGE = 4

    __slots__ = ('recipient_channel', 'reason_code', 'description', 'language_tag')
    _field_types = (Uint32, ReasonCode, Utf8String, ByteString)


class ChannelWindowAdjust(SshMessage, msg_type=SshMessage.MessageType.CHANNEL_WINDOW_ADJUST):
    __slots__ = ('recipient_channel', 'bytes_to_add')
    _field_types = (Uint32, Uint32)


class ChannelData(SshMessage, msg_type=SshMessage.MessageType.CHANNEL_DATA):
    __slots__ = ('recipient_channel', 'data')
    _field_types = (Uint32, ByteString)


class ChannelExtendedData(SshMessage, msg_type=SshMessage.MessageType.CHANNEL_EXTENDED_DATA):
    class DataTypeCode(Uint32, Enum):
        STDERR = 1

    __slots__ = ('recipient_channel', 'data_type_code', 'data')
    _field_types = (Uint32, DataTypeCode, ByteString)


class ChannelEOF(SshMessage, msg_type=SshMessage.MessageType.CHANNEL_EOF):
    __slots__ = ('recipient_channel',)
    _field_types = (Uint32,)


class ChannelClose(SshMessage, msg_type=SshMessage.MessageType.CHANNEL_CLOSE):
    __slots__ = ('recipient_channel',)
    _field_types = (Uint32,)


class ChannelRequest(SshMessage, msg_type=SshMessage.MessageType.CHANNEL_REQUEST):
    __slots__ = ('recipient_channel', 'request_type', 'want_reply')
    _field_types = (Uint32, AsciiString, Boolean)


class ChannelRequestPTY(ChannelRequest, request_type='pty-req'):
    class EncodedTerminalModes(int, Field, Enum):
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

        def parse(self, flow):
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

    __slots__ = ('TERM',
                 'terminal_width_ch', 'terminal_height_ch',
                 'terminal_width_px', 'terminal_height_px',
                 'encoded_terminal_modes')
    _field_types = (AsciiString,
                    Uint32, Uint32,
                    Uint32, Uint32,
                    EncodedTerminalModes)


class ChannelRequestShell(ChannelRequest, request_type='shell'):
    __slots__ = ()
    _field_types = ()


# Compatibility. TODO: DROPME
BinarySshPacket = SshMessage
