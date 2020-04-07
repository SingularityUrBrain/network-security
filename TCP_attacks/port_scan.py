import argparse
import socket
import sys
import time

parser = argparse.ArgumentParser(description='Port scanner')
parser.add_argument('host')
parser.add_argument('-p0', dest='start_port', type=int,
                    help='port to scan from', required=True)
parser.add_argument('-p1', dest='end_port', type=int,
                    help='port to scan to, if no end port specified only the start port will be checked')
args = parser.parse_args()

host = args.host
start_port = args.start_port
end_port = args.end_port if args.end_port else start_port+1
target_ip = socket.gethostbyname(host)
for port in range(start_port, end_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex((target_ip, port))
    if result == 0:
        print(f'{port} port open')
    # time.sleep(0.01)
