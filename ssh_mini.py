import socket
import random

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("delos.imag.fr", 22))
print("connexion established")

s_w = s.makefile(mode="w")
s_r = s.makefile(mode="r")

print("Sending version")
s_w.write("SSH-2.0-pyhton_tim&henry_1.0")
s_w.flush()
data = s_r.readline()
print("Found version: %s" % data)

message = b""
message += b"\x00"  # Padding
message += b"\x14"  # Key init
#message += bytes[random.randint(0, 0xFFFFFFFF).to_bytes(4, "big") for i in range(4)]
message += b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
message = len(message).to_bytes(4, 'big') + message
s_w.write(message.decode("utf-8"))
s_w.flush()
print("Sent '%s'" % message.decode("utf-8"))
data = s_r.read(32)
print("Found data: %s" % data)
