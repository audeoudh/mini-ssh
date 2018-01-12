import abc

import fields


class AuthenticationKey:
    algo_name = None
    known_key_types = {}

    @staticmethod
    def supported_algorithm(algo_name):
        def decorator(cls):
            AuthenticationKey.known_key_types[algo_name] = cls
            cls.algo_name = algo_name

        return decorator

    @classmethod
    @abc.abstractclassmethod
    def from_public_blob(cls, blob): ...

    @abc.abstractmethod
    def sign(self, data): ...

    @abc.abstractmethod
    def public_blob(self): ...

    def _format_public_blob(self, blob):
        return fields.StringType('ascii').to_bytes(self.algo_name) + blob

    def _format_signature(self, data):
        return fields.StringType('ascii').to_bytes(self.algo_name) + \
               fields.StringType('octet').to_bytes(data)
