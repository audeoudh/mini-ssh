import base64


def parse_public_key_file(filename):
    """Parse a public key file and return the found fields"""
    with open(filename, 'rb') as f:
        return _parse_public_key_line(f.readline())


def _parse_public_key_line(line):
    fields = line.split(b" ", 2)
    keytype = fields.pop(0).decode('ascii')
    key_blob = base64.decodebytes(fields.pop(0))
    try:
        comment = fields.pop(0).decode('utf-8')
    except IndexError:
        comment = None  # No comment on this line

    return keytype, key_blob, comment
