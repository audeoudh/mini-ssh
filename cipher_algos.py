import abc

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class CipherAlgo(metaclass=abc.ABCMeta):
    supported = {}

    @property
    @abc.abstractmethod
    def key_length(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def name(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def block_size(self):
        raise NotImplementedError()

    def __init_subclass__(cls):
        super().__init_subclass__()
        CipherAlgo.supported[cls.name] = cls

    @abc.abstractmethod
    def encrypt(self, payload) -> bytes:
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt(self, payload) -> bytes:
        raise NotImplementedError()


class NoneCipher(CipherAlgo):
    """A cipher that does nothing.

    Used as default cipher."""

    name = "none"
    key_length = 0
    block_size = 1

    def encrypt(self, payload):
        return payload

    def decrypt(self, payload):
        return payload


class Aes128Ctr(CipherAlgo):
    _name = "aes128-ctr"
    _key_length = 16
    _block_size = 16

    def __init__(self, iv_bytes, key_bytes):
        super().__init__()
        IV = iv_bytes[:self.key_length]
        key = key_bytes[:self.key_length]
        self._cipher = Cipher(algorithms.AES(key), modes.CTR(IV), backend=default_backend())
        self._encryptor = self._cipher.encryptor()
        self._decryptor = self._cipher.decryptor()

    @property
    def name(self):
        return self._name

    @property
    def block_size(self):
        return self._block_size

    @property
    def key_length(self):
        return self._key_length

    def encrypt(self, payload):
        return self._encryptor.update(payload)

    def decrypt(self, payload):
        return self._decryptor.update(payload)
