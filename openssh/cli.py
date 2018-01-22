import argparse
import logging
import os
import sys

from openssh.main import main
from openssh.defaults import *


def cli(args=None):
    """Parsing of command-line arguments.

    The interface is expected to be compatible with OpenSSH (not yet completely
    supported).

    :param args: a command-line style list of arguments. The default is to use
      the sys.args value."""

    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "-v", dest="verbose", action="count", default=0,
        help="Verbose mode.  Causes ssh to print debugging messages about its "
             "progress.  This is helpful in debugging connection, "
             "authentication, and configuration problems.  Multiple -v "
             "options increase the verbosity.  The maximum is 2.")
    argparser.add_argument(
        "-p", dest='port', default=DEFAULT_PORT,
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
