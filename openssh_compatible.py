import argparse
import base64
import getpass
import logging
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import authentication_keys
from messages import MethodName
from ssh_engine import SshEngine

logger = logging.getLogger(__name__)

DEFAULT_PRIVATE_KEYS = \
    tuple(os.path.join(os.path.expanduser("~"), '.ssh', key_filename)
          for key_filename in ('id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa'))


def cli(args=None):
    """Parsing of command-line arguments"""

    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "-v", dest="verbose", action="count", default=0,
        help="Verbose mode.  Causes ssh to print debugging messages about its "
             "progress.  This is helpful in debugging connection, "
             "authentication, and configuration problems.  Multiple -v "
             "options increase the verbosity.  The maximum is 2.")
    argparser.add_argument(
        "-p", dest='port', default=22,
        help="Port to connect to on the remote host")
    argparser.add_argument(
        "-l", dest='login_name',
        help="Specifies the user to log in as on the remote machine")
    argparser.add_argument(
        "destination", metavar="[user@]hostname",
        help="The remote machine to which ssh should connect, and the user "
             "name to use while performing authentication")
    options = argparser.parse_args(args)

    # Configure verbosity of logger
    try:
        log_level = (logging.WARNING, logging.INFO, logging.DEBUG)[options.verbose]
    except IndexError:
        log_level = logging.DEBUG  # Maximum verbosity
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=log_level)

    # Check the port
    if not (0x0000 < options.port <= 0xFFFF):
        print("Bad port '%d'" % options.port, file=sys.stderr)
        exit(255)

    # Parse the destination
    try:
        # Erase login_name if already defined: this form is preferred
        options.login_name, hostname = options.destination.rsplit("@", 1)
    except ValueError:
        # No login_name. Ok.
        hostname = options.destination

    # Check the username
    if options.login_name == "":
        argparser.print_help(file=sys.stderr)
        exit(255)
    elif options.login_name is None:
        options.login_name = os.environ['USER']

    sys.exit(main(options.login_name, hostname, options.port))


def main(user_name, server_name, port,
         available_keys_filenames=DEFAULT_PRIVATE_KEYS):
    with SshEngine(user_name, server_name, port) as sshc:

        # Authenticate with a key
        for key_filename in available_keys_filenames:
            # Check if method is supported
            if not sshc.is_authentication_method_supported(MethodName.PUBLICKEY):
                break

            # Load public key
            public_key_filename = key_filename + '.pub'
            try:
                with open(public_key_filename, 'rb') as file:
                    algo_name, blob, comment = file.read().split(b" ", 2)
                    algo_name = algo_name.decode('ascii')
                    public_key_blob = base64.decodebytes(blob)
                    comment = comment.decode('utf-8')
            except FileNotFoundError:
                # Ok, just no such key, normal.
                continue
            except PermissionError:
                logger.warning("%s: unreadable file", public_key_filename)
                continue
            except IOError as e:
                logger.warning("%s: cannot open file: %s", public_key_filename, e)
                continue
            try:
                key_class = authentication_keys.AuthenticationKey.known_key_types[algo_name]
            except IndexError:
                logger.warning("%s: %s: unsupported key type", public_key_filename, algo_name)
                continue
            try:
                key = key_class.from_public_blob(public_key_blob)
            except ValueError:
                logger.warning("%s: invalid %s key", public_key_filename, algo_name)
                continue

            # Test public key
            logger.debug("Offering public key from %s", public_key_filename)
            if not sshc.authenticate_with_public_key(key):
                logger.info("Key in %s is refused", public_key_filename)
                continue

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
                break

        # Authenticate with the password
        while not sshc.is_authenticated() and \
                sshc.is_authentication_method_supported(MethodName.PASSWORD):
            the_password = getpass.getpass(prompt="%s@%s's password: " % (sshc.user_name, sshc.server_name))
            sshc.authenticate(password=the_password)
            if not sshc.is_authenticated():
                print("Permission denied, please try again.", file=sys.stderr)

        # Should be authenticated now
        if not sshc.is_authenticated():
            print("%s@%s: Permission denied (%s)." %
                  (sshc.user_name, sshc.server_name,
                   ",".join(sshc._userauth_reply.authentications_that_can_continue)))
            return 255


if __name__ == '__main__':
    cli()
