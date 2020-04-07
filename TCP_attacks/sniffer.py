import argparse

from scapy.all import *


def is_packet_on_tcp_conn(server_ip, server_port, client_ip):
    def f(p):
        return (
            is_packet_tcp_server_to_client(server_ip, server_port, client_ip)(p) or
            is_packet_tcp_client_to_server(
                server_ip, server_port, client_ip)(p)
        )
    return f


def is_packet_tcp_server_to_client(server_ip, server_port, client_ip):
    def f(p):
        if not p.haslayer(TCP):
            return False
        src_ip = p[IP].src
        src_port = p[TCP].sport
        dst_ip = p[IP].dst
        return src_ip == server_ip and src_port == server_port and dst_ip == client_ip
    return f


def is_packet_tcp_client_to_server(server_ip, server_port, client_ip):
    def f(p):
        if not p.haslayer(TCP):
            return False
        src_ip = p[IP].src
        dst_ip = p[IP].dst
        dst_port = p[TCP].dport
        return src_ip == client_ip and dst_ip == server_ip and dst_port == server_port
    return f


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Port scanner')
    parser.add_argument('iface', help='network interface')
    parser.add_argument('host', help='IP to sniff')
    parser.add_argument('port', help='port to sniff', type=int)
    args = parser.parse_args()

    localhost_ip = args.host
    print("Starting sniff...")
    t = sniff(
        iface=args.iface,
        count=0,
        prn=lambda p: p.show(),
        lfilter=is_packet_tcp_client_to_server(localhost_ip, args.port, localhost_ip))
    print("Done.")
