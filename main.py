import socket
import time
from concurrent.futures import ThreadPoolExecutor
import argparse

parser = argparse.ArgumentParser(
        prog="rescan",
        description="Pizza made port scanner",
        epilog="Thank you for trying %(prog)s! =P"
)

mandatory = parser.add_argument_group("Mandatory arguments")
mandatory.add_argument("-H", "--host", help="Host to perform the scan on. Eg: 192.168.56.101")
mandatory.add_argument("-sS",action="store_true", help="TCP SYN Scan")
mandatory.add_argument("-sU",action="store_true", help="UDP Scan")
mandatory.add_argument("-sF",action="store_true", help="TCP FIN Scan")
mandatory.add_argument("-sT",action="store_true", help="TCP Connect Scan")

optional = parser.add_argument_group("Optional arguments")
optional.add_argument("-t", "--timing", help="1 - Stealthy; 2 - Calm; 3 - Normal; 4 - Fast; 5 - Aggressive")
optional.add_argument("-p", "--port", help="Ports to scan. Eg: 80; 21,22,80; 1-1023")

args = parser.parse_args()

HOST = args.host
synScan = args.sS
udpScan = args.sU
finScan=args.sF
conScan=args.sT
timing = args.timing
port = args.port
open_ports = []
closed_ports = []

def load_ports(filepath):
        with open(filepath,'r') as f:
                return [int(line.strip()) for line in f if line.strip()]

TCP_PORTS = load_ports('data/top_tcp_ports.txt')
UDP_PORTS = load_ports('data/top_udp_ports.txt')

print(UDP_PORTS)                        

def scan_port(HOST, PORT):
        global open_ports, closed_ports
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
                s.connect((HOST,PORT))
                open_ports.append(PORT)
        except:
                closed_ports.append(PORT)       


if(conScan):
        if(synScan or udpScan or finScan):
                print("Please choose only one scan type")
        else:
                print(f"Executing TCP Connect Scan on host {HOST}: ")
                with ThreadPoolExecutor(max_workers=100) as executor:
                        for PORT in range(1,1023):
                                executor.submit(scan_port, HOST, PORT)
        print(f"Open ports: {open_ports}")
else:
        print('')