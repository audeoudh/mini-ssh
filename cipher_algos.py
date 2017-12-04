import abc

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class CipherAlgo(metaclass=abc.ABCMeta):
    supported = {}

    @property
    @abc.abstractmethod
    def name(self):
        raise NotImplementedError()

    @property
    def block_size(self):
        raise NotImplementedError()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        CipherAlgo.supported[cls.name] = cls

    def encrypt(self, payload) -> bytes:
        raise NotImplementedError()

    def decrypt(self, payload) -> bytes:
        raise NotImplementedError()


class NoneCipher:
    """A cipher that does nothing.

    Used as default cipher."""

    name = "none"
    block_size = 1

    def encrypt(self, payload):
        return payload

    def decrypt(self, payload):
        return payload


class Aes128Ctr(NoneCipher):
    name = "aes128-ctr"
    block_size = 16
    key_size = 16

    def __init__(self, iv_bytes, key_bytes):
        super().__init__()
        IV = iv_bytes[:self.key_size]
        key = key_bytes[:self.key_size]
        self._cipher = Cipher(algorithms.AES(key), modes.CTR(IV), backend=default_backend())
        self._encryptor = self._cipher.encryptor()
        self._decryptor = self._cipher.decryptor()

    def encrypt(self, payload):
        return self._encryptor.update(payload)

    def decrypt(self, payload):
        return self._decryptor.update(payload)
