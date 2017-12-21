import argparse

import os

import sys

from ssh_engine import SshEngine


def cli(args=None):
    """Parsing of command-line arguments"""

    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "destination", metavar="[user@]hostname",
        help="The remote machine to which ssh should connect, and the user "
             "name to use while performing authentication")
    options = argparser.parse_args(args)

    # Parse the destination
    login_name = None
    try:
        # Erase login_name if already defined: this form is preferred
        login_name, hostname = options.destination.rsplit("@", 1)
    except ValueError:
        # No login_name. Ok.
        hostname = options.destination

    # Check the username
    if login_name == "":
        argparser.print_help(file=sys.stderr)
        exit(255)
    elif login_name is None:
        login_name = os.environ['USER']

    main(login_name, hostname, 22)


def main(user_name, server_name, port):
    with SshEngine(user_name, server_name, port) as sshc:
        pass


if __name__ == '__main__':
    cli()
