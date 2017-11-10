# Implementation of SSH field types. See RFC4251 section 5.

import abc
from typing import Any, Union

NETWORK_BYTE_ORDER = 'big'


class FieldType(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def from_bytes(self, flow: bytes) -> Any:
        raise NotImplementedError

    @abc.abstractmethod
    def to_bytes(self, value: Any) -> bytes:
        raise NotImplementedError


class ByteType(FieldType):
    def from_bytes(self, flow) -> (int, int):
        return 1, flow[0]

    def to_bytes(self, value: int):
        return value.to_bytes(1, NETWORK_BYTE_ORDER)


class BytesType(FieldType):
    # This is the same type as the one defined by Byte; however, as Python
    # distinguishes between int and bytes, we separate a one-byte field (an
    # integer) from a n-bytes field.
    def __init__(self, length):
        self.length = length

    def from_bytes(self, flow) -> (int, bytes):
        return self.length, flow[:self.length]

    def to_bytes(self, value: bytes):
        if len(value) == self.length:
            return value
        else:
            raise Exception("Unable to fit %d bytes in a %d-byte field"
                            % (len(value), self.length))


class BooleanType(FieldType):
    def from_bytes(self, flow) -> (int, bool):
        return 1, flow[0] != 0

    def to_bytes(self, value: bool):
        if value:
            return b"\x01"
        else:
            return b"\x00"


class Uint32Type(FieldType):
    def from_bytes(self, flow) -> (int, int):
        return 4, int.from_bytes(flow[0:4], NETWORK_BYTE_ORDER, signed=False)

    def to_bytes(self, value: int):
        return value.to_bytes(4, NETWORK_BYTE_ORDER, signed=False)


class Uint64Type(FieldType):
    def from_bytes(self, flow) -> (int, int):
        return 8, int.from_bytes(flow[0:8], NETWORK_BYTE_ORDER, signed=False)

    def to_bytes(self, value: int):
        return value.to_bytes(8, NETWORK_BYTE_ORDER, signed=False)


class StringType(FieldType):
    len_field = Uint32Type()

    def __init__(self, encoding):
        self.encoding = encoding

    def from_bytes(self, flow) -> (int, Union[str, bytes]):
        """If encoding is "octet", read a raw octet-string and return a bytes object. Or,
        decode it according to the encoding"""
        read_len, string_size = self.len_field.from_bytes(flow)
        string = flow[read_len:(read_len + string_size)]
        if self.encoding != "octet":
            string = string.decode(self.encoding)
        read_len += string_size
        return read_len, string

    def to_bytes(self, value: Union[str, bytes]):
        length = self.len_field.to_bytes(len(value))
        string = value
        if self.encoding != "octet":
            string = value.encode(self.encoding)
        return length + string


class MpintType(FieldType):
    len_field = Uint32Type()

    def from_bytes(self, flow) -> (int, bytes):
        read_len, mpi_len = self.len_field.from_bytes(flow)
        mpi = flow[read_len:(read_len + mpi_len)]
        read_len += mpi_len
        return read_len, mpi

    def to_bytes(self, value: bytes):
        length = self.len_field.to_bytes(len(value))
        return length + value


class NameListType(FieldType):
    len_field = Uint32Type()

    def from_bytes(self, flow) -> (int, list):
        read_len, list_len = self.len_field.from_bytes(flow)
        list_ = flow[read_len:(read_len + list_len)].decode("ascii").split(",")
        read_len += list_len
        return read_len, list_

    def to_bytes(self, value: list):
        list_ = ",".join(value).encode("ascii")
        length = self.len_field.to_bytes(len(list_))
        return length + list_
