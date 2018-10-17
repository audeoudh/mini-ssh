import abc
import hashlib


class HashAlgo(metaclass=abc.ABCMeta):
    supported = {}  # All supported algo names

    @property
    @abc.abstractmethod
    def name(self):
        raise NotImplementedError

    def __init_subclass__(cls):
        super().__init_subclass__()
        HashAlgo.supported[cls.name] = cls

    @property
    @abc.abstractmethod
    def digest_length(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def hash(self, data):
        raise NotImplementedError()


class Sha256(HashAlgo):
    _name = "sha256"
    _digest_length = 32

    @property
    def name(self):
        return self._name

    @property
    def digest_length(self):
        return self._digest_length

    def hash(self, data):
        return hashlib.sha256(data).digest()
