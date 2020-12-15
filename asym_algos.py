# Copyright 2018 Henry-Joseph Audéoud & Timothy Claeys
#
# This file is part of mini-ssh.
#
# mini-ssh is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# mini-ssh is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with mini-ssh.  If not, see
# <https://www.gnu.org/licenses/>.

import abc

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
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
        return key.public_bytes(serialization.Encoding.X962,
                                serialization.PublicFormat.UncompressedPoint)

    @property
    def name(self):
        return self._name

    def generate_key_pair(self):
        self._client_ephemeral_private_key = ec.generate_private_key(self._curve, default_backend())
        self.client_ephemeral_public_key = self._client_ephemeral_private_key.public_key()

    def compute_shared_secret(self):
        return self._client_ephemeral_private_key.exchange(ec.ECDH(), self.server_ephemeral_public_key)
