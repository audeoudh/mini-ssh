import os

DEFAULT_PRIVATE_KEYS = \
    tuple(os.path.join(os.path.expanduser("~"), '.ssh', key_filename)
          for key_filename in ('id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa'))

DEFAULT_PORT = 22
