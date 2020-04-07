import datetime as dt
import hashlib
import socket
import json
import time
import os

from des import DesKey


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')


def send_encrypted(sock, addr, key: DesKey, data: bytes):
    sock.sendto(key.encrypt(data), addr)


def as_req(sock: socket, server_address, c, key_c: DesKey):
    sock.sendto(b'AS_REQ', server_address)
    sock.sendto(c.encode('utf-8'), server_address)
    t1 = int_to_bytes(int(dt.datetime.utcnow().timestamp()))
    send_encrypted(sock, server_address, key_c, t1)


def as_rep(sock: socket, key_c: DesKey, tgt_path, data_path):
    data = sock.recv(1024)
    if b'Error' in data:
        raise Exception(data.decode('utf-8')[7:])
    data = key_c.decrypt(data)
    data = json.loads(data)
    # save key
    with open(data_path, 'w') as jf:
        json.dump(data, jf)
    tgt = sock.recv(1024)
    # save ticket
    with open(tgt_path, 'wb') as f:
        f.write(tgt)
    return data, tgt


def tgs_req(sock: socket, tgs_address, c, ss, tgt, key_c_tgs: DesKey):
    sock.sendto(b'TGS_REQ', tgs_address)
    sock.sendto(tgt, tgs_address)
    sock.sendto(ss.encode('utf-8'), tgs_address)
    t2 = int(dt.datetime.utcnow().timestamp())
    aut1 = json.dumps([c, t2]).encode('utf-8')
    send_encrypted(sock, tgs_address, key_c_tgs, aut1)


def tgs_rep(sock: socket, key_c_tgs: DesKey):
    data_tgs = sock.recv(1024)
    if b'Error' in data_tgs:
        print(data_tgs.decode('utf-8'))
        return None
    st = sock.recv(1024)
    data_tgs = key_c_tgs.decrypt(data_tgs)
    data_tgs = json.loads(data_tgs)
    return data_tgs, st


def ss_req(sock: socket, ss_address, c, t4, st: bytes, key_c_ss: DesKey):
    sock.sendto(b'SS_REQ', ss_address)
    aut2 = json.dumps([c, t4]).encode('utf-8')
    sock.sendto(st, ss_address)
    send_encrypted(sock, ss_address, key_c_ss, aut2)


def is_auth(data_path, tgt_path):
    return os.path.isfile(data_path) and os.path.isfile(tgt_path)


def main():
    server_address = ('localhost', 9999)  # authentication server address
    ss_id = '1efeggrvv'  # id of service server
    ss_address = ('localhost', 5000)  # address of service server
    tgt_path = 'tgt'
    data_path = 'data.json'

    login = input('login: ')
    password = input('password: ').encode('utf-8')
    # create key from hash of password
    m = hashlib.sha256()
    m.update(password)
    key_c = DesKey(m.digest()[:8])

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        is_authenticated = is_auth(data_path, tgt_path)
        # Loop while we are not authorized
        while True:
            # skip authentication if we already have tgt
            if is_authenticated:
                with open('data.json') as f1, open('tgt', 'rb') as f2:
                    data = json.load(f1)
                    tgt = f2.read()
            else:
                # AS_REQ
                as_req(sock, server_address, login, key_c)
                # AS_REP
                data, tgt = as_rep(sock, key_c, tgt_path, data_path)

            key_c_tgs, tgs_address, p1 = data
            # key_c_tgs is a string key
            key_c_tgs = DesKey(key_c_tgs.encode('utf-8'))
            # tgs_address is a list (need a tuple)
            tgs_address = tuple(tgs_address)
        # TGS_REQ
            tgs_req(sock, tgs_address, login, ss_id, tgt, key_c_tgs)
        # TGS_REP
            tgs_rep_data = tgs_rep(sock, key_c_tgs)
            if tgs_rep_data:
                break
            else:
                is_authenticated = False

        data_tgs, st = tgs_rep_data
        key_c_ss, ss, p2 = data_tgs
        # key_c_ss is a string key
        key_c_ss = DesKey(key_c_ss.encode('utf-8'))
    # SS_REQ
        t4 = int(dt.datetime.utcnow().timestamp())
        ss_req(sock, ss_address, login, t4, st, key_c_ss)
    # SS_REP
        t_c1 = sock.recv(1024)
        t_c1 = int(key_c_ss.decrypt(t_c1))
        if t_c1 - t4 == 1:
            print('Success authorization :)')
        else:
            print('Server is not authorized!')


if __name__ == "__main__":
    main()
