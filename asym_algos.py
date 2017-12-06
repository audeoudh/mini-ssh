import abc

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec


class AsymAlgo(metaclass=abc.ABCMeta):
    supported = {}

    @property
    @abc.abstractmethod
    def key_size(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def generate_key_pair(self):
        raise NotImplementedError()


class KeyExchange(AsymAlgo):
    supported = {}

    def __init_subclass__(cls):
        super().__init_subclass__()
        KeyExchange.supported[cls.name] = cls

    @property
    @abc.abstractmethod
    def name(self):
        raise NotImplementedError()


class EcdhSha2Nistp256(KeyExchange):
    _name = "ecdh-sha2-nistp256"
    _curve = ec.SECP256R1()
    _key_size = 256

    def __init__(self):
        self._client_ephemeral_private_key = None
        self.client_ephemeral_public_key = None
        self.server_ephemeral_public_key = None
        self.generate_key_pair()

    @property
    def curve(self):
        return self._curve

    @property
    def key_size(self):
        # actual key size is unknown so, return size of curve
        return self._key_size

    @classmethod
    def to_point_encoding(cls, key):
        return key.public_numbers().encode_point()

    @property
    def name(self):
        return self._name

    def generate_key_pair(self):
        self._client_ephemeral_private_key = ec.generate_private_key(self._curve, default_backend())
        self.client_ephemeral_public_key = self._client_ephemeral_private_key.public_key()

    def compute_shared_secret(self):
        return self._client_ephemeral_private_key.exchange(ec.ECDH(), self.server_ephemeral_public_key)




