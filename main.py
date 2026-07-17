import socket
import time
from concurrent.futures import ThreadPoolExecutor
import argparse
import re
import sys
import os

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
ports = args.port
open_ports = []
closed_ports = []
scanned_ports = []
openFiltered_ports =[]

portPattern = r'^\d+(-\d+)?(,\d+(-\d+)?)*$'

def load_ports(filepath):
        with open(filepath,'r') as f:
                return [int(line.strip()) for line in f if line.strip()]


def tcp_scan_port(HOST, PORT):
        global open_ports, closed_ports
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
                s.connect((HOST,PORT))
                open_ports.append(PORT)
        except:
                closed_ports.append(PORT)       


def udp_scan_port(HOST, PORT):
        global open_ports, closed_ports, openFiltered_ports
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        try:
                s.connect((HOST,PORT))
                s.send(b"")
                data = s.recv(1024)
                open_ports.append(PORT)
        except ConnectionRefusedError:
                closed_ports.append(PORT)
        except socket.timeout:
                openFiltered_ports.append(PORT)
        finally:
                s.close()
                
if(ports!=None):
        if(re.fullmatch(portPattern,ports) == None):
                print("Thrown error - port argument doesn't match the supported format")
                sys.exit(1)
        else:
                ports = ports.strip()
                portData = ports.split(',')
                for part in portData:
                        if '-' in part:
                                start = int(part.split('-')[0])
                                end = int(part.split('-')[1])
                                for i in range(start,end+1):
                                        scanned_ports.append(i)
                        else:
                                scanned_ports.append(int(part))
else:
        TCP_PORTS = load_ports('data/top_tcp_ports.txt')
        UDP_PORTS = load_ports('data/top_udp_ports.txt')                              
                   

if(conScan):
        
        if(synScan or udpScan or finScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        scanned_ports = TCP_PORTS
                print(f"Executing TCP Connect Scan on host {HOST}: ")
                with ThreadPoolExecutor(max_workers=100) as executor:
                        for PORT in scanned_ports:
                                executor.submit(tcp_scan_port, HOST, PORT)
        print(f"\n----------------------------------------------")
        print(f"Port       -      Status      -       Protocol")
        print(f"----------------------------------------------")
        for port in open_ports:
                print(f"{port}       -       Open       -       Protocol")

elif(udpScan):
       
        if(synScan or conScan or finScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        scanned_ports = UDP_PORTS
                print(f"Executing UDP Scan on {HOST}: ")
                with ThreadPoolExecutor(max_workers=30) as executor:
                        for PORT in scanned_ports:
                                executor.submit(udp_scan_port, HOST, PORT)
                print(f"Open ports: {sorted(open_ports)}")
                print(f"Closed ports: {sorted(closed_ports)}")
                print(f"Open or filtered ports: {sorted(openFiltered_ports)}")