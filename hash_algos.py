import abc
import hashlib


class HashAlgo(metaclass=abc.ABCMeta):
    supported = {}  # All supported algo names

    @property
    @abc.abstractmethod
    def name(self):
        raise NotImplementedError()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__()
        HashAlgo.supported[cls.name] = cls

    @abc.abstractmethod
    def hash(self, data):
        raise NotImplementedError()


class EcdhSha2Nistp256(HashAlgo):
    name = "ecdh-sha2-nistp256"

    def hash(self, data):
        return hashlib.sha256(data).digest()
