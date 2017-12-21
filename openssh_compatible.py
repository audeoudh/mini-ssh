import argparse

import os

import sys

from ssh_engine import SshEngine


def cli(args=None):
    """Parsing of command-line arguments"""

    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "-p", metavar="port", default=22,
        help="Port to connect to on the remote host")
    argparser.add_argument(
        "-l", metavar="login_name",
        help="Specifies the user to log in as on the remote machine")
    argparser.add_argument(
        "destination", metavar="[user@]hostname",
        help="The remote machine to which ssh should connect, and the user "
             "name to use while performing authentication")
    options = argparser.parse_args(args)

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

    main(options.login_name, hostname, options.port)


def main(user_name, server_name, port):
    with SshEngine(user_name, server_name, port) as sshc:
        pass


if __name__ == '__main__':
    cli()
