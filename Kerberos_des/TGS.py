import datetime as dt
import hashlib
import json
import secrets
import socketserver
import string

from des import DesKey

K_TGS = DesKey(b'istgskey')
K_SS = DesKey(b'itssskey')
services = ['1efeggrvv', 'ueb90dvdb']


class MyUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        print(data)
        if data == b'TGS_REQ':
            tgt = socket.recv(1024)
            ss = socket.recv(1024).decode('utf-8')
            aut1 = socket.recv(1024)
            if ss not in services:
                socket.sendto(b'Error: invalid ss_id', self.client_address)
                return
            tgt = K_TGS.decrypt(tgt)
            c1, key_c_tgs, p1, t_kdc = json.loads(tgt)
            key_c_tgs = DesKey(key_c_tgs.encode('utf-8'))
            aut1 = key_c_tgs.decrypt(aut1)
            aut1 = json.loads(aut1)
            c2, t_c = aut1
            t_c = dt.datetime.fromtimestamp(t_c)
            t_kdc = dt.datetime.fromtimestamp(t_kdc)
            delta = (t_c - t_kdc).total_seconds()
            print(c1, c2, delta, p1)
        # TGS_REP
            if c1 == c2 and delta/3600 < p1:
                key_c_ss = ''.join(secrets.choice(
                    string.ascii_letters + string.digits) for _ in range(8))
                p2 = 10   # hours
                data_c_tgs = json.dumps(
                    [key_c_ss, ss, p2]).encode('utf-8')
                data_c_tgs = key_c_tgs.encrypt(data_c_tgs)
                socket.sendto(data_c_tgs, self.client_address)
                t3 = int(dt.datetime.utcnow().timestamp())
                tgs = json.dumps(
                    [c1, ss, t3, p2, key_c_ss]).encode('utf-8')
                tgs = K_SS.encrypt(tgs)
                socket.sendto(tgs, self.client_address)
            else:
                socket.sendto(b'Error: Unauthorized', self.client_address)


if __name__ == "__main__":
    HOST, PORT = "localhost", 10000
    socketserver.UDPServer.allow_reuse_address = True
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()
