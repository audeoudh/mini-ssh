import os

DEFAULT_PRIVATE_KEYS = \
    tuple(os.path.join(os.path.expanduser("~"), '.ssh', key_filename)
          for key_filename in ('id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa'))

DEFAULT_PORT = 22

DEFAULT_KNOWN_HOSTS = \
    (os.path.join(os.sep, "etc", "ssh", "ssh_known_hosts"),
     os.path.join(os.path.expanduser("~"), '.ssh', 'known_hosts'))

DEFAULT_STRICT_HOST_KEY_CHECKING = True
