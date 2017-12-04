import abc
import hashlib
import hmac


class MacAlgo(metaclass=abc.ABCMeta):
    supported = {}  # All supported algo names

    @property
    @abc.abstractmethod
    def name(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def mac_length(self):
        raise NotImplementedError()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__()
        MacAlgo.supported[cls.name] = cls

    @abc.abstractmethod
    def compute_mac(self, payload) -> bytes:
        """Compute the MAC of this payload"""
        raise NotImplementedError()

    def check_mac(self, payload, mac):
        """Raise Exception if given MAC is invalid for this payload."""
        if self.compute_mac(payload) != mac:
            raise Exception("Incorrect MAC detected")


class NoneMAC(MacAlgo):
    """MAC of any message is empty.

    This is the default algorithm, when a connection is started."""
    name = "none"
    mac_length = 0

    def compute_mac(self, payload):
        return b""

    def check_mac(self, payload, mac):
        return mac == b""


class HmacSha2_256(MacAlgo):
    name = "hmac-sha2-256"
    mac_length = 32

    def __init__(self, key):
        self.key = key

    def compute_mac(self, payload):
        return hmac.HMAC(self.key, payload, hashlib.sha256).digest()[:32]
