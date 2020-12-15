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

# Parsing of configuration files, public keys, private keys, etc...
import base64
import enum
import logging

from authentication_keys import AuthenticationKey


class Markers(str, enum.Enum):
    REVOKED = "@revoked"
    CERT_AUTHORITHY = "@cert-auhority"


class KnownHostFile:
    logger = logging.getLogger(__name__)

    def __init__(self, filename):
        self.filename = filename
        self.entries = []
        self._parse()

    def search(self, key, hostname, port=22):
        """Look for an entry in one of the `files` known hosts.

        :return (None, None, None) if not found; else, a tuple:
          - markers for this key
          - hostname pattern that matched the hostname & port
          - the key found in known hosts file"""
        for entry_markers, entry_hostname_pattern, entry_key in self.entries:
            if entry_hostname_pattern.startswith(b"delos"):
                breakpoint()
            if key == entry_key and \
                    self._hostname_match_patterns(hostname, port, entry_hostname_pattern):
                return entry_markers, entry_hostname_pattern, entry_key
        return None, None, None

    def add_key(self, key, hostname, port=22, comment=None):
        """Add an host as known host"""
        if (key, hostname, port) not in self:
            if port != 22:
                hostname = "[%s]:%d" % (hostname, port)

            blob = base64.b64encode(key.public_blob()).decode('ascii')
            line = [hostname, key.algo_name, blob]
            if comment is not None:
                line.append(comment)
            line = " ".join(line)

            with open(self.filename, 'ab') as khf:
                khf.write(line.encode('ascii'))

            self.entries.append((None, hostname, key))

    def contains(self, key, hostname, port=22):
        return self.search(key, hostname, port) != (None, None, None)

    def __contains__(self, item):
        """Accessor for `contains`.  `item` is a tuple of all three args of this method."""
        return self.contains(*item)

    def _parse(self):
        """Parse all entries in the known-hosts file.

        An entry have five fields:
        * the marker (@revoked, @cert-authority or None)
        * the list of hostname patterns
        * the key type
        * the public key blob
        * a comment (possibly None as it is optional).

        Empty and comment lines are ignored."""
        self.logger.info("Parsing known-hosts file '%s'", self.filename)
        with open(self.filename, 'rb') as f:
            line_no = 0
            for line in f:
                line_no += 1
                if line == b'\n' or line.startswith(b'#'):
                    # Lines starting with ‘#’ and empty lines are ignored as comments.
                    continue

                line = line.rstrip(b"\n")
                if line.startswith(b"@"):
                    marker, line = line.split(b" ", 1)
                    marker = Markers(marker.decode('ascii'))
                else:
                    marker = None
                hostname_pattern, line = line.split(b" ", 1)

                self.logger.debug("Found a public key for '%s'", hostname_pattern)

                line_fields = line.split(b" ", 2)
                key_type = line_fields.pop(0).decode('ascii')
                key_blob = base64.decodebytes(line_fields.pop(0))
                try:
                    comment = line_fields.pop(0).decode('utf-8')
                except IndexError:
                    comment = None  # No comment on this line

                key = AuthenticationKey.from_blob(key_blob, comment)
                if key.algo_name != key_type:
                    self.logger.warning("Key for '%s' (line %d) is a '%s' key, but is declared as '%s'",
                                        hostname_pattern, line_no, key.algo_name, key_type)

                self.entries.append((marker, hostname_pattern, key))

    def _hostname_match_patterns(self, hostname, port, pattern):
        breakpoint()
        if pattern.startswith(b"|"):
            # TODO: handle the case when hostnames are hashed
            return False
        else:
            patterns = pattern.decode('ascii').split(",")
            # TODO: support *, !, ports, etc…
            return hostname in patterns


def parse_public_key_file(filename):
    """Parse a public key file and return the found fields"""
    with open(filename, 'rb') as f:
        line = f.readline()
    fields = line.split(b" ", 2)
    keytype = fields.pop(0).decode('ascii')
    key_blob = base64.decodebytes(fields.pop(0))
    try:
        comment = fields.pop(0).decode('utf-8')
    except IndexError:
        comment = None  # No comment on this line

    key = AuthenticationKey.from_blob(key_blob)

    if key.algo_name != keytype:
        logging.warning(f"Key in {filename} do not use its declared algorithm!")

    return key.algo_name, key_blob, comment
