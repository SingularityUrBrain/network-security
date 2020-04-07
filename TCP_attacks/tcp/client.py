import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', int(sys.argv[1]))
print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)

while 1:
    mess = input().encode('utf8')
    sock.sendall(mess)
    print(sock.recv(512))
