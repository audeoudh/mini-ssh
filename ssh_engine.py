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

import logging
import os
import select
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

import asym_algos
import fields
import hash_algos
from authentication_keys import AuthenticationKey
from messages import *
from transport import Transport


class SshEngine:
    logger = logging.getLogger(__name__)

    client_version = "SSH-2.0-python_tim&henry_0.1"

    def __init__(self, user_name, server_name, port=22):
        self.user_name = user_name
        self.server_name = server_name
        self.port = port
        self.server_version = None
        self.socket = None
        self.server_key = None
        self._session_id = None
        self._userauth_reply = None

    @property
    def session_id(self):
        """The session identifier. If the session is not currently initialized, None."""
        return self._session_id

    def __enter__(self):
        # Start transport layer
        self.socket = Transport()
        self.socket.connect((self.server_name, self.port))

        # Start SSH connection
        self.version_exchange()
        self.key_exchange()
        self.init_authentication()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self.socket.close()

    def version_exchange(self):
        self.server_version = self.socket.exchange_versions(self.client_version)

    def key_exchange(self):
        """Do a whole key exchange, as described in RFC 4253"""
        self.logger.info("Exchange key mechanism activated...")

        # Generate a dh object for the key exchange and pick a random session cookie
        self.dh = asym_algos.EcdhSha2Nistp256()
        cookie = os.urandom(16)

        # Key Exchange Init: exchange the supported crypto algorithms, first algo in list is preferred one
        client_kexinit = KexInit(
            cookie=cookie,
            kex_algo=("ecdh-sha2-nistp256",), server_host_key_algo=tuple(AuthenticationKey.known_key_types.keys()),
            encryption_algo_ctos=("aes128-ctr",), encryption_algo_stoc=("aes128-ctr",),
            mac_algo_ctos=("hmac-sha2-256",), mac_algo_stoc=("hmac-sha2-256",),
            compression_algo_ctos=("none",), compression_algo_stoc=("none",),
            languages_ctos=(), languages_stoc=(),
            first_kex_packet_follows=False)

        self.socket.send_ssh_msg(client_kexinit)
        server_kexinit = self.socket.recv_ssh_msg()
        if not isinstance(server_kexinit, KexInit):
            raise Exception("First packet is not a KEI packet")
        self.logger.info("Key Exchange Init phase: ok")

        # Key Exchange Diffie-Hellman: create a shared secret
        client_kex_ecdh = KexDHInit(
            e=asym_algos.EcdhSha2Nistp256.to_point_encoding(self.dh.client_ephemeral_public_key))
        self.socket.send_ssh_msg(client_kex_ecdh)
        server_kex_ecdh = self.socket.recv_ssh_msg()
        if not isinstance(server_kex_ecdh, KexDHReply):
            raise Exception("not a KEXDH_REPLY packet")
        self.server_key = AuthenticationKey.from_blob(server_kex_ecdh.server_public_key)

        kex_hash_algo = hash_algos.Sha256()  # Currently forced. TODO: make it modifiable

        # construct a 'public key' object from the received server public key
        self.dh.server_ephemeral_public_key = \
            ec.EllipticCurvePublicKey.from_encoded_point(self.dh.curve, server_kex_ecdh.f)

        # multiply server's ephemeral public key with client's ephemeral private key --> shared secret
        shared_secret = self.dh.compute_shared_secret()
        self.logger.info("Key Exchange Diffie-Hellman phase: ok")

        # Compute exchange hash
        class ExchangeHash(BinarySshPacket):
            # Not really a SSH packet, but we use the same method to get the payload.

            __slots__ = ('client_version', 'server_version',
                         'client_kexinit', 'server_kexinit',
                         'host_key',
                         'client_exchange_value', 'server_exchange_value',
                         'shared_secret')

            _field_types = (StringType('ascii'), StringType('ascii'),
                            StringType('octet'), StringType('octet'),
                            StringType('octet'),
                            StringType('octet'), StringType('octet'),
                            MpintType())

        client_kexinit_bytes = client_kexinit.msg_type.to_bytes(1, 'big') + client_kexinit.payload()
        server_kexinit_bytes = server_kexinit.msg_type.to_bytes(1, 'big') + server_kexinit.payload()
        to_be_hashed = ExchangeHash(
            client_version=self.client_version, server_version=self.server_version,
            client_kexinit=client_kexinit_bytes, server_kexinit=server_kexinit_bytes,
            host_key=server_kex_ecdh.server_public_key,
            client_exchange_value=client_kex_ecdh.e, server_exchange_value=server_kex_ecdh.f,
            shared_secret=int.from_bytes(shared_secret, 'big', signed=False))
        key_exchange_hash = kex_hash_algo.hash(to_be_hashed.payload())

        # Set the session ID:
        # > The exchange hash H from the first key exchange is additionally
        # > used as the session identifier [...] Once computed, the session
        # > identifier is not changed, even if keys are later re-exchanged
        # > [RFC4253]
        if self._session_id is None:
            self._session_id = key_exchange_hash

        # Verify server's signature
        server_public_key_iterator = server_kex_ecdh.server_public_key.__iter__()
        key_type = fields.StringType('ascii').from_bytes(server_public_key_iterator)
        # TODO: support other key types. Here, only ssh-rsa keys are supported.
        assert key_type == 'ssh-rsa'
        rsa_exponent = fields.MpintType().from_bytes(server_public_key_iterator)
        rsa_modulus = fields.MpintType().from_bytes(server_public_key_iterator)
        server_key = rsa.RSAPublicNumbers(e=rsa_exponent, n=rsa_modulus).public_key(default_backend())

        server_signature_iterator = server_kex_ecdh.signature.__iter__()
        key_type = fields.StringType('ascii').from_bytes(server_signature_iterator)
        # TODO: support other key types. Here, only ssh-rsa keys are supported.
        assert key_type == 'ssh-rsa'
        signature = fields.StringType('octet').from_bytes(server_signature_iterator)

        server_key.verify(signature, key_exchange_hash, padding.PKCS1v15(), hashes.SHA1())
        self.logger.info("Server signature verification: ok")

        # New Keys: switch to the new cyphering method
        self.socket.send_ssh_msg(NewKeys())
        nk = self.socket.recv_ssh_msg()
        if not isinstance(nk, NewKeys):
            raise Exception("not a NEWKEYS packet")

        # Activate the encryption
        self.socket.change_keys(kex_hash_algo, shared_secret, key_exchange_hash, self.session_id)
        self.logger.info("Keys and algorithms change: ok")

    def init_authentication(self):
        # Request the authentication service
        service_request = ServiceRequest(service_name=ServiceName.USERAUTH)
        self.socket.send_ssh_msg(service_request)
        service_accept = self.socket.recv_ssh_msg()
        if not isinstance(service_accept, ServiceAccept):
            raise Exception("not a ServiceAccept message")
        if service_request.service_name != service_accept.service_name:
            raise Exception("The server did not provide the expected service (%s), but provided %s instead." %
                            (service_request.service_name, service_accept.service_name))
        self.logger.debug("Service %s accepted by the server" % service_accept.service_name)

    def authenticate_with_public_key(self, public_key):
        """Try a fake authentication with a public key, without signing the
        message.

        :return True if the an authentication with this key would be accepted by
          the server (but is currently accepted, as we have not signed the
          message)."""
        if not self.is_authentication_method_supported(MethodName.PUBLICKEY):
            return False

        userauth_request = UserauthRequestPublicKey(
            user_name=self.user_name,
            service_name=ServiceName.CONNECTION,
            method_name=MethodName.PUBLICKEY,
            signed=False,
            algorithm_name=public_key.algo_name,
            blob=public_key.public_blob())
        self.socket.send_ssh_msg(userauth_request)
        userauth_reply = self.socket.recv_ssh_msg()

        return userauth_reply.msg_type == SshMsgType.USERAUTH_PK_OK

    def is_authentication_method_supported(self, method):
        """Check if the authentication method is supported.

        If no UserauthFailure is received yet, suppose that this authentication
        is supported. If we guess wrong, remote server will provide the needed
        list of supported authentication methods."""
        if self._userauth_reply is None:
            return True  # Suppose that yes…
        return method in self._userauth_reply.authentications_that_can_continue

    def authenticate(self, password=None, private_key=None):
        # Compute the correct UserauthRequest
        if password is not None and \
                self.is_authentication_method_supported(MethodName.PASSWORD):
            userauth_request = UserauthRequestPassword(
                user_name=self.user_name,
                service_name=ServiceName.CONNECTION,
                method_name=MethodName.PASSWORD,
                change_password=False,
                password=password)

        elif private_key is not None and \
                self.is_authentication_method_supported(MethodName.PUBLICKEY):
            userauth_request = UserauthRequestPublicKey(
                user_name=self.user_name,
                service_name=ServiceName.CONNECTION,
                method_name=MethodName.PUBLICKEY,
                signed=False,
                algorithm_name=private_key.algo_name,
                blob=private_key.public_blob())
            userauth_request.sign(self._session_id, private_key)

        else:
            userauth_request = UserauthRequestNone(
                user_name=self.user_name,
                service_name=ServiceName.CONNECTION)

        # Send & receive authentication messages
        self.socket.send_ssh_msg(userauth_request)
        userauth_reply = self.socket.recv_ssh_msg()
        if not isinstance(userauth_reply, (UserauthFailure, UserauthSuccess)):
            raise Exception("Unexpected packet type here!")
        self._userauth_reply = userauth_reply

        return isinstance(self._userauth_reply, UserauthSuccess)

    def is_authenticated(self):
        return isinstance(self._userauth_reply, UserauthSuccess)

    def _open_channel(self):
        local_channel_identifier = 1  # Should certainly be fixed later!

        # Open the channel
        channel_open = ChannelOpen(
            channel_type="session",
            sender_channel=local_channel_identifier,
            initial_window_size=2 ** 16 - 1,
            maximum_packet_size=256)
        self.socket.send_ssh_msg(channel_open)
        open_confirmation = self.socket.recv_ssh_msg()
        if isinstance(open_confirmation, ChannelOpenFailure):
            raise Exception("Unable to open channel")

        # Request a pseudo-terminal
        # channel_request = ChannelRequestPTY(
        #     recipient_channel=open_confirmation.sender_channel,
        #     want_reply=False,
        #     TERM="xterm-256color",
        #     terminal_width_ch=80,
        #     terminal_height_ch=24,
        #     terminal_width_px=0,
        #     terminal_height_px=0,
        #     encoded_terminal_modes=((ChannelRequestPTY.EncodedTerminalModes.IMAXBEL, 0),))
        # self.socket.send_ssh_msg(channel_request)

        # Request a shell
        channel_request = ChannelRequestShell(
            recipient_channel=open_confirmation.sender_channel,
            want_reply=False)
        self.socket.send_ssh_msg(channel_request)
        print(repr(self.socket.recv_ssh_msg()))  # WindowAdjust
        print(repr(self.socket.recv_ssh_msg()))  # ExtendedData

        # Send a command
        while True:
            readable, _, _ = select.select((self.socket, sys.stdin), (), ())
            if sys.stdin in readable:
                command_str = sys.stdin.readline()
                command = ChannelData(
                    recipient_channel=open_confirmation.sender_channel,
                    data=command_str.encode('ascii'))
                self.socket.send_ssh_msg(command)
            if self.socket in readable:
                msg = self.socket.recv_ssh_msg()
                print(repr(msg))
                if isinstance(msg, ChannelClose) and msg.recipient_channel == local_channel_identifier:
                    msg = ChannelClose(recipient_channel=open_confirmation.sender_channel)
                    self.socket.send_ssh_msg(msg)
                    break
