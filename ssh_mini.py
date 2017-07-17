import socket
from contextlib import closing

with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
    s.connect(("delos.imag.fr", 22))
    print("connexion established")

    s_w = s.makefile(mode="wb")
    s_r = s.makefile(mode="rb")

    print("Sending version")
    s_w.write(b"SSH-2.0-pyhton_tim&henry_1.0\r\n")
    s_w.flush()
    data = s_r.readline()
    print("Found server version: %s" % data.decode("utf-8"))

    message = b""
    message += b"\x00"  # Padding
    message += b"\x14"  # Key init
    message += b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
    message = len(message).to_bytes(4, 'big') + message
    s_w.write(message)
    s_w.flush()
    print("Sent %s" % message)
    data = s_r.read(32)
    print("Found data: %s" % data)
