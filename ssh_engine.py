import getpass
import logging
import os
import select
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

import fields
import hash_algos
from messages import *
from transport import Transport


class SshEngine:
    logger = logging.getLogger(__name__)

    client_version = "SSH-2.0-python_tim&henry_1.0"

    def __init__(self, user_name, server_name, port=22):
        self.user_name = user_name
        self.server_name = server_name
        self.port = port
        self.socket = None
        self._session_id = None

    @property
    def session_id(self):
        """The session identifier. If the session is not currently initialized, None."""
        return self._session_id

    def __enter__(self):
        # Start transport layer
        self.socket = Transport()
        self.socket.connect((self.server_name, self.port))

        # Compute the session identifier

        # Server's ephemeral public key param
        self.point_encoded_server_epub = None
        self.server_epub_key = None

        # Start SSH connection
        self._version()
        self._key_exchange()
        self._authenticate()
        # Needed for openSSH (we currently have strong requirements for the message flow
        _ = self.socket.recv_ssh_msg()  # GlobalRequest<request_name='hostkeys-00@openssh.com', want_reply=False>
        self._open_channel()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close()

    def _version(self):
        self.server_version = self.socket.exchange_versions(self.client_version)

    def _key_exchange(self):
        """Do a whole key exchange, as described in RFC 4253"""
        self.logger.info("Exchange key mechanism activated...")

        # Compute some locally chosen values
        self._ephemeral_private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
        cookie = os.urandom(16)

        # Key Exchange Init: exchange the supported crypto algorithms
        client_kexinit = KexInit(
            cookie=cookie,
            kex_algo=("ecdh-sha2-nistp256",), server_host_key_algo=("ssh-rsa",),
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
            e=self._ephemeral_private_key.public_key().public_numbers().encode_point())
        self.socket.send_ssh_msg(client_kex_ecdh)
        server_kex_ecdh = self.socket.recv_ssh_msg()
        if not isinstance(server_kex_ecdh, KexDHReply):
            raise Exception("not a KEXDH_REPLY packet")

        kex_hash_algo = hash_algos.EcdhSha2Nistp256()  # Currently forced. TODO: make it modifiable

        # construct a 'public key' object from the received server public key
        curve = ec.SECP256R1()
        self._server_ephemeral_public_key = \
            ec.EllipticCurvePublicNumbers.from_encoded_point(curve, server_kex_ecdh.f) \
                .public_key(default_backend())

        # multiply server's ephemeral public key with client's ephemeral private key --> shared secret
        shared_secret = self._ephemeral_private_key.exchange(ec.ECDH(), self._server_ephemeral_public_key)
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

    def _authenticate(self):
        """Perform the client authentication, as described in RFC 4252."""

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

        # Try the "none" authentication
        userauth_request = UserauthRequestNone(
            user_name=self.user_name,
            service_name=ServiceName.CONNECTION)
        self.socket.send_ssh_msg(userauth_request)
        userauth_reply = self.socket.recv_ssh_msg()
        if not isinstance(userauth_reply, (UserauthFailure, UserauthSuccess)):
            raise Exception("Unexpected packet type here!")

        if isinstance(userauth_reply, UserauthSuccess):
            # Waw! Authentication succeed after "none" authentication! Cool!
            return

        while True:
            # Check if we can continue the authentication with a password (currently sole authentication supported)
            if MethodName.PASSWORD not in userauth_reply.authentications_that_can_continue:
                raise Exception("Cannot continue authentication: password not supported by the server")

            # Authenticate with the password
            the_password = getpass.getpass(prompt='Password for %s@%s: ' % (self.user_name, self.server_name))
            userauth_request = UserauthRequestPassword(
                user_name=self.user_name,
                service_name=ServiceName.CONNECTION,
                method_name=MethodName.PASSWORD,
                change_password=False,
                password=the_password)
            self.socket.send_ssh_msg(userauth_request)
            userauth_reply = self.socket.recv_ssh_msg()
            if not isinstance(userauth_reply, (UserauthFailure, UserauthSuccess)):
                raise Exception("Unexpected packet type here!")

            if isinstance(userauth_reply, UserauthSuccess):
                # Ok. We are authenticated
                return

    def _close(self):
        self.socket.close()

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
                print(repr(self.socket.recv_ssh_msg()))
