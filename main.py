import socket
import time
from concurrent.futures import ThreadPoolExecutor
import argparse
import re
import sys
import os
from scapy.all import IP, TCP, sr1, send, ICMP
import threading

def silent_excepthook(args):
    if "sndrcv" in str(args.thread.name):
        return
    threading.__excepthook__(args)

threading.excepthook = silent_excepthook

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
mandatory.add_argument("-sH",action="store_true", help="Host Discovery Scan")

optional = parser.add_argument_group("Optional arguments")
optional.add_argument("-t", "--timing", help="1 - Stealthy; 2 - Calm; 3 - Normal; 4 - Fast; 5 - Aggressive")
optional.add_argument("-p", "--port", help="Ports to scan. Eg: 80; 21,22,80; 1-1023")

args = parser.parse_args()

HOST = args.host
synScan = args.sS
udpScan = args.sU
finScan=args.sF
conScan=args.sT
hostScan = args.sH
timing = args.timing
ports = args.port

open_ports = []
closed_ports = []
scanned_ports = []
openFiltered_ports =[]

valid_hosts = []

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


def syn_scan_port(HOST, PORT):
        global open_ports, closed_ports
        try:
                syn_packet = IP(dst=HOST) / TCP(dport=PORT, flags='S')
                response = sr1(syn_packet, timeout=1, verbose=0)
                if response is None:
                        pass
                elif response.haslayer(TCP):
                        if response[TCP].flags == 'SA':
                                open_ports.append(PORT)
                                rst_packet = IP(dst=HOST) / TCP(dport=PORT, flags='R')
                                send(rst_packet, verbose=0)
                        elif response[TCP].flags == 'R':
                                closed_ports.append(PORT)
                        else:
                                closed_ports.append(PORT)
        except Exception as e:
                pass

        
def fin_scan_port(HOST, PORT):
        global open_ports, closed_ports, openFiltered_ports
        try:
                fin_packet = IP(dst=HOST) / TCP(dport=PORT, flags='F')
                response = sr1(fin_packet, timeout=10, verbose=0)
                if response is None:
                        open_ports.append(PORT)
                elif(response.haslayer(TCP)):
                        if(response.getlayer(TCP).flags == 0x14):
                                closed_ports.append(PORT)
                elif(response.haslayer(ICMP)):
                        if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                openFiltered_ports.append(PORT)
        except Exception as e:
                pass
                                       

def host_scan(HOST):
        global valid_hosts
        try:
                packet = IP(dst=HOST) / ICMP()
                response = sr1(packet, timeout=1, verbose=0)
                if response and response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
                        valid_hosts.append(HOST)
                        return
                packet = IP(dst=HOST) / TCP(dport=443, flags='S')
                response = sr1(packet, timeout=1, verbose=0)
                if(response and response.haslayer(TCP) and response[TCP].flags == 'SA'):
                        valid_hosts.append(HOST)
                        return
                packet = IP(dst=HOST) / TCP(dport=80, flags='A')
                response = sr1(packet, timeout=1, verbose=0)
                if(response and response.haslayer(TCP) and response[TCP].flags == 'R'):
                        valid_hosts.append(HOST)
                        return
                packet = IP(dst=HOST) / ICMP(type=13)
                response = sr1(packet, timeout=1, verbose=0)
                if(response and response.haslayer(ICMP) and response.getlayer(ICMP).type == 14):
                        valid_hosts.append(HOST)
                        return
        except Exception as e:
                pass
                
                
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
        if(synScan or udpScan or finScan or hostScan):
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
       
        if(synScan or conScan or finScan or hostScan):
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

                
elif(synScan):
        if(conScan or udpScan or finScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        scanned_ports = TCP_PORTS
                print(f"Executing TCP Syn Scan on {HOST}: ")
                with ThreadPoolExecutor(max_workers=50) as executor:
                        for PORT in scanned_ports:
                                executor.submit(syn_scan_port, HOST, PORT)
                print(f"\n----------------------------------------------")
                print(f"Port       -      Status      -       Protocol")
                print(f"----------------------------------------------")
                for port in sorted(open_ports):
                        print(f"{port}       -       Open       -       Protocol")

elif(finScan):
        if(conScan or udpScan or synScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        scanned_ports = TCP_PORTS
                print(f"Executing TCP Fin Scan on {HOST}: ")
                with ThreadPoolExecutor(max_workers=50) as executor:
                        for PORT in scanned_ports:
                                executor.submit(fin_scan_port, HOST, PORT)
                print(f"\n----------------------------------------------")
                print(f"Port       -      Status      -       Protocol")
                print(f"----------------------------------------------")
                for port in sorted(open_ports):
                        print(f"{port}       -       Open       -       Protocol")

elif(host_scan):
        if(conScan or udpScan or synScan or finScan):
                print("Please choose only one scan type")
        else:
                print(f"Executing Host Discovery Scan on {HOST}")
                host_scan(HOST)
                print(f"\n-------------------------------------")
                print(f"Host                 -     Status")
                print(f"-------------------------------------")
                for host in valid_hosts:
                        print(f"{host}       -      Open")
                print("\n")