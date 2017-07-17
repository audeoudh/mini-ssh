import socket
from contextlib import closing


def packet_kei(cookie=b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02",
               kex_algo=b"curve25519-sha256", server_host_key_algo=b"ecdsa-sha2-nistp256-cert-v01@openssh.com",
               encryption_algo_ctos=b"aes128-ctr", encryption_algo_stoc=b"aes128-ctr",
               mac_algo_ctos=b"hmac-sha2-512", mac_algo_stoc=b"hmac-sha2-512",
               compression_algo_ctos=b"none", compression_algo_stoc=b"none",
               languages_ctos=b"", languages_stoc=b""):
    message = b"\x14"  # Message code: Key Exchange Init
    message += cookie
    message += len(kex_algo).to_bytes(4, 'big') + kex_algo
    message += len(server_host_key_algo).to_bytes(4, 'big') + server_host_key_algo
    message += len(encryption_algo_ctos).to_bytes(4, 'big') + encryption_algo_ctos
    message += len(encryption_algo_stoc).to_bytes(4, 'big') + encryption_algo_stoc
    message += len(mac_algo_ctos).to_bytes(4, 'big') + mac_algo_ctos
    message += len(mac_algo_stoc).to_bytes(4, 'big') + mac_algo_stoc
    message += len(compression_algo_ctos).to_bytes(4, 'big') + compression_algo_ctos
    message += len(compression_algo_stoc).to_bytes(4, 'big') + compression_algo_stoc
    message += len(languages_ctos).to_bytes(4, 'big') + languages_ctos
    message += len(languages_stoc).to_bytes(4, 'big') + languages_stoc
    message += b"\x00"  # KEX first packet follows
    message += b"\x00\x00\x00\x00"  # reserved

    # Padding
    pad_len = 8 - len(message) % 8
    if pad_len < 4:
        pad_len += 8
    message = pad_len.to_bytes(1, 'big') + message + b"\00" * pad_len

    # Packet length
    message = len(message).to_bytes(4, 'big') + message

    return message


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

    message = packet_kei()
    s_w.write(message)
    s_w.flush()
    print("Sent %s" % message)
    data = s_r.read(32)
    print("Found data: %s" % data)
