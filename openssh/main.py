import getpass
import logging
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import authentication_keys
from hash_algos import Sha256
from messages import MethodName
from openssh.defaults import *
from openssh.helpers import *
from ssh_engine import SshEngine

logger = logging.getLogger(__name__)


def main(user_name, server_name, port,
         available_keys_filenames=DEFAULT_PRIVATE_KEYS):
    """Main entry-point of a OpenSSH-style ssh client.

    :param user_name: the login name
    :param server_name: the remote server name
    :param port: the remote server port
    :param available_keys_filenames: list of paths that are expected to contain
      private keys. Try to use these keys for authentication.

    As this method expects to be executed as main program, it exits with the
    exit() call if an error occurs. Catch SystemExit or us directly SshEngine if
    you want to avoid the whole process to stop."""

    with SshEngine(user_name, server_name, port) as sshc:
        if not check_host_key(server_name, port, sshc):
            print("Host key verification failed.", file=sys.stderr)
            exit(255)
        authenticate(sshc, available_keys_filenames)


def authenticate(sshc, available_keys_filenames):
    # Authenticate with a key
    available_keys = iter(available_keys_filenames)
    try:
        while not sshc.is_authenticated() and \
                sshc.is_authentication_method_supported(MethodName.PUBLICKEY):
            authenticate_with_key(sshc, next(available_keys))
    except StopIteration:
        pass

    # Authenticate with the password
    while not sshc.is_authenticated() and \
            sshc.is_authentication_method_supported(MethodName.PASSWORD):
        authenticate_with_password(sshc)

    # Should be authenticated now
    if not sshc.is_authenticated():
        print("%s@%s: Permission denied (%s)." %
              (sshc.user_name, sshc.server_name,
               ",".join(sshc._userauth_reply.authentications_that_can_continue)))
        exit(255)


def authenticate_with_key(sshc, key_filename):
    # Load public key
    public_key_filename = key_filename + '.pub'
    try:
        key_type, key_blob, comment = parse_public_key_file(public_key_filename)
    except FileNotFoundError:
        # Ok, just no such key. Not an error.
        return False
    except PermissionError:
        logger.warning("%s: unreadable file", public_key_filename)
        return False
    except IOError as e:
        logger.warning("%s: cannot open file: %s", public_key_filename, e)
        return False
    try:
        key = authentication_keys.AuthenticationKey.from_blob(key_blob)
    except KeyError:
        logger.warning("%s: %s: unsupported key type", public_key_filename, key_type)
        return False
    except ValueError:
        logger.warning("%s: invalid %s key", public_key_filename, key_type)
        return False

    # Test public key
    logger.debug("Offering public key from %s", public_key_filename)
    if not sshc.authenticate_with_public_key(key):
        logger.info("Key in %s is refused", public_key_filename)
        return False

    # Load private key
    logger.debug("Load private key from %s", key_filename)
    with open(key_filename, 'rb') as file:
        private_key_file_content = file.read()
    try:
        key.private_key = serialization.load_pem_private_key(
            private_key_file_content, password=None, backend=default_backend())
    except TypeError:
        passphrase = getpass \
            .getpass(prompt="Enter passphrase for key '%s': " % key_filename) \
            .encode('utf-8')
        key.private_key = serialization.load_pem_private_key(
            private_key_file_content, password=passphrase, backend=default_backend())

    # Authenticate with private key
    if sshc.authenticate(private_key=key):
        logger.info("Authentication with %s succeed", key_filename)
        return True
    return False


def authenticate_with_password(sshc):
    the_password = getpass.getpass(
        prompt="%s@%s's password: " % (sshc.user_name, sshc.server_name))
    sshc.authenticate(password=the_password)
    if not sshc.is_authenticated():
        print("Permission denied, please try again.", file=sys.stderr)


def check_host_key(hostname, port, sshc,
                   known_hosts_filenames=DEFAULT_KNOWN_HOSTS,
                   strict_host_key_checking=DEFAULT_STRICT_HOST_KEY_CHECKING):
    """Check if the given public key & host is known"""
    marker, key_blob, comment = \
        known_hosts_search(hostname, port, sshc.server_key, filenames=known_hosts_filenames)
    readable_key_type = sshc.server_key.algo_name.upper()

    if key_blob is None or sshc.server_key.public_blob() != key_blob.public_blob():
        # Key not found, or found but does not match
        if strict_host_key_checking == 'yes':
            print("No %s host key is known for %s and you have requested strict "
                  "checking." % (hostname, readable_key_type),
                  file=sys.stderr)
            return False
        elif strict_host_key_checking == 'ask':
            print("The authenticity of host '%s (%s)' can't be established.\n"
                  "%s key fingerprint is %s." %
                  (hostname, sshc.socket.getsockname()[0], readable_key_type, sshc.server_key.fingerprint(Sha256())),
                  file=sys.stderr)
            response = input("Are you sure you want to continue connecting (yes/no)? ")
            while response not in ("yes", "no"):
                response = input("Please type 'yes' or 'no': ")
            if response == "yes":
                known_hosts_add_key(hostname, port, sshc.server_key, None)
                print("Warning: Permanently added '%s' (%s) to the list of known hosts." %
                      (hostname, readable_key_type), file=sys.stderr)
                return True
            return False
        elif (strict_host_key_checking == 'accept-new' and key_blob is None) or \
                strict_host_key_checking in ('no', 'off'):
            # Accepted this time
            known_hosts_add_key(hostname, port, sshc.server_key, None)
            print("Warning: Permanently added '%s' (%s) to the list of known hosts." %
                  (hostname, readable_key_type), file=sys.stderr)
            return True
        else:
            return False

    elif marker == Markers.REVOKED:
        # “@revoked”, to indicate that the key contained on the line is
        # revoked and must not ever be accepted.
        print(
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            "@       WARNING: REVOKED HOST KEY DETECTED!               @\n"
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            "The %s host key for %s is marked as revoked.\n"
            "This could mean that a stolen key is being used to\n"
            "impersonate this host." % (readable_key_type, hostname),
            file=sys.stderr)
        if strict_host_key_checking in ('no', 'off'):
            # Not a problem for us
            # TODO: just deactivate keyboard-based authentication
            return True
        print("%s host key for %s was revoked and you have requested strict checking.\n"
              "Host key verification failed." % (readable_key_type, hostname),
              file=sys.stderr)
        return False

    elif marker == '@cert-authority':
        raise NotImplementedError("@cert-authority keys are not supported yet")

    else:  # Correct and valid key
        return True
