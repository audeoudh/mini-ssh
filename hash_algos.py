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
