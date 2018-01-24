# Parsing of configuration files, public keys, private keys, etc...
import base64
import enum

from authentication_keys import AuthenticationKey


class Markers(str, enum.Enum):
    REVOKED = "@revoked"
    CERT_AUTHORITHY = "@cert-auhority"


def known_hosts_add_key(hostname, port, key, comment):
    raise NotImplementedError


def known_hosts_search(hostname, port, key, filenames):
    """Look for an entry in one of the `files` known hosts.

    :return a tuple composed of the marker, the key blob, and the comment that
      match the given hostname, port and blob. If such entry cannot be found,
      return another entry that matches the hostname and port, but not the blob
      (i.e. another key for the same host)"""
    fallback_result = None, None, None
    blob = key.public_blob()
    for filename in filenames:
        for marker, hostname_pattern, key_type, key_blob, comment \
                in parse_known_hosts_file(filename):
            if _hostname_match_patterns(hostname, port, hostname_pattern):
                entry_key = AuthenticationKey.from_blob(key_blob)
                if blob == key_blob:
                    return marker, entry_key, comment
                else:
                    # Maybe we will have a better result later
                    fallback_result = marker, entry_key, comment
    # No perfect match, return an imperfect one
    return fallback_result


def _hostname_match_patterns(hostname, port, pattern):
    if pattern.startswith(b"|"):
        # TODO: handle the case when hostnames are hashed
        return False
    else:
        patterns = pattern.decode('ascii').split(",")
        # TODO: support *, !, ports, etc…
        return hostname in patterns


def parse_known_hosts_file(filename):
    """Yield all entries of the given known_host file

    An entry holds five fields:
    * the marker (@revoked, @cert-authority or None)
    * the list of hostname patterns
    * the key type
    * the public key blob
    * a comment (possibly None as it is optional).

    Empty and comment lines are ignored."""
    try:
        with open(filename, 'rb') as f:
            for line in f:
                if line == b'\n' or line.startswith(b'#'):
                    # Lines starting with ‘#’ and empty lines are ignored as comments.
                    continue

                line = line.rstrip(b"\n")
                if line.startswith(b"@"):
                    marker, line = line.split(b" ", 1)
                    marker = Markers(marker.decode('ascii'))
                else:
                    marker = None
                hostnames_pattern, line = line.split(b" ", 1)

                yield (marker, hostnames_pattern, *_parse_public_key_line(line))
    except FileNotFoundError:
        # No entries here
        pass


def parse_public_key_file(filename):
    """Parse a public key file and return the found fields"""
    with open(filename, 'rb') as f:
        return _parse_public_key_line(f.readline())


def _parse_known_host_line(line):


    return ()


def _parse_public_key_line(line):
    fields = line.split(b" ", 2)
    keytype = fields.pop(0).decode('ascii')
    key_blob = base64.decodebytes(fields.pop(0))
    try:
        comment = fields.pop(0).decode('utf-8')
    except IndexError:
        comment = None  # No comment on this line

    return keytype, key_blob, comment
