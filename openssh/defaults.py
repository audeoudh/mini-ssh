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

import os

DEFAULT_PRIVATE_KEYS = \
    tuple(os.path.join(os.path.expanduser("~"), '.ssh', key_filename)
          for key_filename in ('id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa'))

DEFAULT_PORT = 22

DEFAULT_KNOWN_HOSTS = \
    (os.path.join(os.sep, "etc", "ssh", "ssh_known_hosts"),
     os.path.join(os.path.expanduser("~"), '.ssh', 'known_hosts'))

DEFAULT_STRICT_HOST_KEY_CHECKING = "ask"  # 'no', 'off', 'ask', 'accept-new', 'yes'
