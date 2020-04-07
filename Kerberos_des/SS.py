import datetime as dt
import hashlib
import json
import secrets
import socketserver
import string

from des import DesKey

K_SS = DesKey(b'itssskey')


class MyUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        print(data)
        if data == b'SS_REQ':
            tgs = socket.recv(1024)
            aut2 = socket.recv(1024)

            tgs = K_SS.decrypt(tgs)
            print('tgs:', tgs)
            c1, ss, t3, p2, key_c_ss = json.loads(tgs)
            # key_c_ss is a string key
            key_c_ss = DesKey(key_c_ss.encode('utf-8'))
            aut2 = key_c_ss.decrypt(aut2)
            c2, t4 = json.loads(aut2)

            t3 = dt.datetime.fromtimestamp(t3)
            t4_dt = dt.datetime.fromtimestamp(t4)
            delta = (t4_dt-t3).total_seconds()
            if c1 == c2 and delta/3600 < p2:
                t4 = key_c_ss.encrypt(str(t4+1).encode('utf-8'))
                socket.sendto(t4, self.client_address)
            else:
                socket.sendto(b'Error: Unathorized', self.client_address)


if __name__ == "__main__":
    HOST, PORT = "localhost", 5000
    socketserver.UDPServer.allow_reuse_address = True
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()
