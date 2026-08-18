import socket
import time
from concurrent.futures import ThreadPoolExecutor
import argparse
import re
import sys
import os
from scapy.all import IP, TCP, sr1, send, ICMP, arping
import threading
import ipaddress
import logging
import json
from data.payloads import udp_payloads

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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
mandatory.add_argument("-H", "--host", help="Host to perform the scan on. Eg: 192.168.56.101",required=True)
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

scanned_hosts = []

open_ports = []
closed_ports = []
scanned_ports = []
openFiltered_ports =[]
TCP_PORTS = []
UDP_PORTS = []

valid_hosts = set()
hostname_map = dict()

portPattern = r'^\d+(-\d+)?(,\d+(-\d+)?)*$'

TIMING_PROFILES = {
        "1": {"timeout": 3.0, "workers": 5},
        "2": {"timeout": 1.5, "workers": 20},
        "3": {"timeout": 1, "workers": 50},
        "4": {"timeout": 0.5, "workers": 100},
        "5": {"timeout": 0.3, "workers": 200}
}

def is_hostname(HOST):
        try:
                ipaddress.ip_address(HOST)
                return False
        except ValueError:
                return True
        
def load_ports(filepath):
        with open(filepath,'r') as f:
                return [int(line.strip()) for line in f if line.strip()]

def load_services():
        with open('data/services.json', 'r') as f:
                services = json.load(f)
        return services

def get_timing_profile():
        if timing is None:
                return TIMING_PROFILES["3"]
        if timing not in TIMING_PROFILES:
                print("Timing options: 1 - Stealthy; 2 - Calm; 3 - Normal; 4 - Fast; 5 - Aggressive")
                sys.exit(1)
        return TIMING_PROFILES[timing]

timing_profile = get_timing_profile()

def parse_hosts(HOST):
        parts = HOST.split(',')
        global scanned_hosts
        for part in parts:
                if(is_hostname(part)):
                        try:
                                hostname_map[socket.gethostbyname(part)] = part
                                part = socket.gethostbyname(part)                     
                                try:
                                        arping(part, timeout=timing_profile["timeout"], verbose=0)
                                        ip = ipaddress.ip_address(part)
                                        scanned_hosts.append(str(ip))
                                except ValueError:
                                        print(f"Invalid IP address:{part}")
                                        return      
                        except socket.gaierror:
                                print(f"Could not resolve hostname: {part}")
                                continue
                elif '-' in part:
                        try:
                                arping(part, timeout=timing_profile["timeout"], verbose=0)
                                start_ip = ipaddress.ip_address(part.split('-')[0])
                                end_ip = ipaddress.ip_address(part.split('-')[1])
                                if(start_ip > end_ip):
                                        print("Invalid IP Range")
                                        return
                                current_ip = start_ip
                                while current_ip <= end_ip:
                                        scanned_hosts.append(str(current_ip))
                                        current_ip = current_ip + 1
                        except ValueError:
                                print("Invalid IP format")
                                return
                elif '/' in part:
                        try:
                                arping(part, timeout=timing_profile["timeout"], verbose=0)
                                net = ipaddress.ip_network(part, strict=False)
                                for ip in net.hosts():
                                        scanned_hosts.append(str(ip))
                        except ValueError:
                                print("Invalid CIDR format")
                                return
                else:
                        try:
                                arping(part, timeout=timing_profile["timeout"], verbose=0)
                                ip = ipaddress.ip_address(part)
                                scanned_hosts.append(str(ip))
                        except ValueError:
                                print(f"Invalid IP address:{part}")
                                return
def tcp_scan_port(HOST, PORT):
        global open_ports, closed_ports
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timing_profile["timeout"])
        try:
                s.connect((HOST,PORT))
                open_ports.append(PORT)
        except:
                closed_ports.append(PORT)       

def udp_scan_port(HOST, PORT):
        global open_ports, closed_ports, openFiltered_ports
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timing_profile["timeout"])
        try:
                payload = udp_payloads.get(PORT,b"")
                s.connect((HOST,PORT))
                s.send(payload)
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
                response = sr1(syn_packet, timeout=timing_profile["timeout"], verbose=0)
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
                response = sr1(fin_packet, timeout=timing_profile["timeout"], verbose=0)
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
                response = sr1(packet, timeout=timing_profile["timeout"], verbose=0)
                if response and response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
                        valid_hosts.add(HOST)
                        return
                packet = IP(dst=HOST) / TCP(dport=443, flags='S')
                response = sr1(packet, timeout=timing_profile["timeout"], verbose=0)
                if(response and response.haslayer(TCP) and response[TCP].flags == 'SA'):
                        valid_hosts.add(HOST)
                        return
                packet = IP(dst=HOST) / TCP(dport=80, flags='A')
                response = sr1(packet, timeout=timing_profile["timeout"], verbose=0)
                if(response and response.haslayer(TCP) and response[TCP].flags == 'R'):
                        valid_hosts.add(HOST)
                        return
                packet = IP(dst=HOST) / ICMP(type=13)
                response = sr1(packet, timeout=timing_profile["timeout"], verbose=0)
                if(response and response.haslayer(ICMP) and response.getlayer(ICMP).type == 14):
                        valid_hosts.add(HOST)
                        return
        except Exception as e:
                pass

def initial_scan():           
        parse_hosts(args.host)
        if((args.sT or args.sU or args.sF or args.sS) and args.sH == False):
                with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                        for HOST in scanned_hosts:
                                executor.submit(host_scan, HOST)

def initialize_ports():
        global ports, TCP_PORTS, UDP_PORTS, scanned_ports, valid_ports
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

def execute_con_scan():
        global ports, TCP_PORTS, UDP_PORTS, scanned_ports, valid_ports, services
        if(synScan or udpScan or finScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        scanned_ports = TCP_PORTS
                for HOST in sorted(valid_hosts):
                        open_ports.clear()
                        printed_host = hostname_map.get(HOST, HOST)
                        print(f"\nExecuting TCP Connect Scan on host {printed_host}: ")
                        with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                                for PORT in scanned_ports:
                                        executor.submit(tcp_scan_port, HOST, PORT)
                        print(f"\n----------------------------------------------")
                        print(f"Port       -      Status      -       Protocol")
                        print(f"----------------------------------------------")
                        for port in open_ports:
                                print(f"{port}       -       Open       -       {services["tcp"][str(port)]}")

def execute_udp_scan():
        global ports, TCP_PORTS, UDP_PORTS, scanned_ports, valid_ports, open_ports, closed_ports, openFiltered_ports
        if(synScan or conScan or finScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        scanned_ports = UDP_PORTS
                for HOST in sorted(valid_hosts):
                        open_ports.clear()
                        printed_host = hostname_map.get(HOST, HOST)
                        print(f"Executing UDP Scan on {printed_host}: ")
                        with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                                for PORT in scanned_ports:
                                        executor.submit(udp_scan_port, HOST, PORT)
                        open_ports = list(set(open_ports))
                        closed_ports = list(set(closed_ports))
                        openFiltered_ports = list(set(openFiltered_ports))
                        print(f"\n----------------------------------------------")
                        print(f"Port       -      Status      -       Protocol")
                        print(f"----------------------------------------------")
                        for port in sorted(open_ports):
                                print(f"{port}       -       Open       -       {services["udp"][str(port)]}")
                        for port in sorted(openFiltered_ports):
                                print(f"{port}       -    Open/Filtered    -       {services["udp"][str(port)]}")

def execute_syn_scan():
        global ports, TCP_PORTS, UDP_PORTS, scanned_ports, valid_ports
        if(conScan or udpScan or finScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        scanned_ports = TCP_PORTS
                for HOST in sorted(valid_hosts):
                        open_ports.clear()
                        printed_host = hostname_map.get(HOST, HOST)
                        print(f"Executing TCP Syn Scan on {printed_host}: ")
                        with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                                for PORT in scanned_ports:
                                        executor.submit(syn_scan_port, HOST, PORT)
                        print(f"\n----------------------------------------------")
                        print(f"Port       -      Status      -       Protocol")
                        print(f"----------------------------------------------")
                        for port in sorted(open_ports):
                                print(f"{port}       -       Open       -       {services["tcp"][str(port)]}")

def execute_fin_scan():
        global ports, TCP_PORTS, UDP_PORTS, scanned_ports, valid_ports
        if(conScan or udpScan or synScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        scanned_ports = TCP_PORTS
                for HOST in sorted(valid_hosts):
                        open_ports.clear()
                        printed_host = hostname_map.get(HOST, HOST)
                        print(f"Executing TCP Fin Scan on {printed_host}: ")
                        with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                                for PORT in scanned_ports:
                                        executor.submit(fin_scan_port, HOST, PORT)
                        print(f"\n----------------------------------------------")
                        print(f"Port       -      Status      -       Protocol")
                        print(f"----------------------------------------------")
                        for port in sorted(open_ports):
                                print(f"{port}       -       Open       -       {services["tcp"][str(port)]}")

def execute_host_scan():
        global ports, TCP_PORTS, UDP_PORTS, scanned_ports, valid_ports
        if(conScan or udpScan or synScan or finScan):
                print("Please choose only one scan type")
        else:
                printed_host = hostname_map.get(args.host, args.host)
                print(f"Executing Host Discovery Scan on {printed_host}")
                with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                        for HOST in scanned_hosts:
                                executor.submit(host_scan, HOST)
                print(f"\n-------------------------------------")
                print(f"Host                 -     Status")
                print(f"-------------------------------------")
                for host in sorted(valid_hosts):
                        print(f"{host}       -      Open")
                print("\n")


def run():
        global services
        initial_scan()
        initialize_ports()
        services = load_services()
        if(conScan):
                execute_con_scan()
        elif(udpScan):
                execute_udp_scan()
        elif(synScan):
                execute_syn_scan()
        elif(finScan):
                execute_fin_scan()
        elif(hostScan):
                execute_host_scan()

if __name__ == "__main__":
    run()