import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.settimeout(1)

s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s2.bind(("172.26.181.95", 5550))
print(s2.recvfrom(1024))
