import datetime as dt
import hashlib
import json
import secrets
import socketserver
import string

from des import DesKey

USER_DB = {'nikita': 'nik123123'}
K_TGS = DesKey(b'istgskey')
TGS_ADDRESS = ('localhost', 10000)


class MyUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print(f"{self.client_address[0]} wrote:\n{data}")
        if data == b'AS_REQ':
            user_login = socket.recv(1024).decode('utf-8')
            t1 = socket.recv(1024)
            print(user_login, t1)
            if user_login not in USER_DB:
                socket.sendto(b'Error: You are not in DB', self.client_address)
                return
            password = USER_DB[user_login].encode('utf-8')
            m = hashlib.sha256()
            m.update(password)
            # create key
            self.key_c = DesKey(m.digest()[:8])
            t1_kc = self.key_c.decrypt(t1)
            delta = dt.datetime.utcnow() - dt.datetime.fromtimestamp(int.from_bytes(t1_kc, 'big'))
            if delta.total_seconds()/60 > 5:
                socket.sendto(
                    b'Error: Timezones must be identical or check your password', self.client_address)
                return

        # AS_REP
            # key generation:
            # https://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits/23728630#23728630
            key_c_tgs = ''.join(secrets.choice(
                string.ascii_letters + string.digits) for _ in range(8))
            p1 = 8  # hours
            t_kdc = int(dt.datetime.utcnow().timestamp())
            data_kc = json.dumps([key_c_tgs, TGS_ADDRESS, p1]).encode('utf-8')
            data_kc = self.key_c.encrypt(data_kc)
            socket.sendto(data_kc, self.client_address)
            tgt = json.dumps(
                [user_login, key_c_tgs, p1, t_kdc]).encode('utf-8')
            tgt = K_TGS.encrypt(tgt)
            socket.sendto(tgt, self.client_address)


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    socketserver.UDPServer.allow_reuse_address = True
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()
