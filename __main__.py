import logging

import click

from ssh_engine import SshEngine


@click.command()
@click.argument("remote")
@click.option("-p", required=False, default=22)
def main(remote, p=22):
    parts = remote.split("@")
    if len(parts) == 1:
        user_name = "root"  # TODO: better to extract the username from environment
        server_name = remote
    elif len(parts) == 2:
        user_name = parts[0]
        server_name = parts[1]
    else:
        raise Exception("Unable to find user & server name")

    with SshEngine(user_name, server_name, p) as sshc:
        print("Established")


if __name__ == "__main__":
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
    main()
