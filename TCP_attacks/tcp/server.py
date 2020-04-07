import signal
import socket
import sys
import threading


def on_new_client(clientsocket, addr):
    while True:
        msg = clientsocket.recv(1024)
        print(addr, ' >> ', msg)
        msg = input('server >> ').encode('utf8')
        clientsocket.send(msg)
    clientsocket.close()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def close_connects(signal, frame):
    global s
    s.close()
    sys.exit(0)

signal.signal(signal.SIGINT, close_connects)


host = socket.gethostbyname('localhost')
port = int(sys.argv[1])

print('Server started\nWaiting for clients...')

s.bind((host, port))
s.listen(5)

while True:
    con, addr = s.accept()
    print('Got connection from', addr)
    x = threading.Thread(target=on_new_client, args=(con, addr))
    x.start()
