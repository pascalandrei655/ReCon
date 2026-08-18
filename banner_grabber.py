import socket
import argparse
import re
import ipaddress
import sys
from scapy.all import IP, TCP, sr1, send, ICMP, arping
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import ssl

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def silent_excepthook(args):
    if "sndrcv" in str(args.thread.name):
        return
    threading.__excepthook__(args)

threading.excepthook = silent_excepthook

parser = argparse.ArgumentParser(
        prog="rebanner",
        description="Pizza made banner grabber",
        epilog="Thank you for trying %(prog)s! =P"
)


mandatory = parser.add_argument_group("Mandatory arguments")
mandatory.add_argument("-H", "--host", help="Host to perform the scan on. Eg: 192.168.56.101", required=True)

optional = parser.add_argument_group("Optional arguments")
optional.add_argument("-t", "--timing", help="1 - Stealthy; 2 - Calm; 3 - Normal; 4 - Fast; 5 - Aggressive")
optional.add_argument("-p", "--port", help="Ports to scan. Eg: 80; 21,22,80; 1-1023")

args = parser.parse_args()

HOST = args.host
ports = args.port
timing = args.timing

valid_hosts = set()
scanned_hosts = []
scanned_ports = []
open_ports_by_host = dict()
hostname_map = dict()

portPattern = r'^\d+(-\d+)?(,\d+(-\d+)?)*$'

TIMING_PROFILES = {
        "1": {"timeout": 3.0, "workers": 5},
        "2": {"timeout": 1.5, "workers": 20},
        "3": {"timeout": 1, "workers": 50},
        "4": {"timeout": 0.5, "workers": 100},
        "5": {"timeout": 0.3, "workers": 200}
}

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

banners = dict()

def is_hostname(HOST):
        try:
                ipaddress.ip_address(HOST)
                return False
        except ValueError:
                return True

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
                scanned_ports = load_ports("data/top_tcp_ports.txt")

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
        with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                for HOST in scanned_hosts:
                        executor.submit(host_scan, HOST)

def grab_banner(HOST, PORT):
        global banners
        if int(PORT) in [443, 8443, 9443]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(timing_profile["timeout"])
                s = context.wrap_socket(raw_sock, server_hostname=HOST)
                try:
                        s.connect((HOST, int(PORT)))
                        request = f"HEAD / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
                        s.sendall(request.encode())
                        banner = s.recv(1024).decode('utf-8', errors='replace').strip()
                        if PORT not in banners:
                                banners[PORT] = banner
                except Exception as e:
                        pass
                finally:
                        s.close()
        else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        try:
                                s.settimeout(timing_profile["timeout"])
                                s.connect((HOST, int(PORT)))
                                request = ''
                                if int(PORT) in [80,8080,8000,8888]:
                                        request = f"HEAD / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
                                s.sendall(request.encode())
                                banner = s.recv(1024).decode('utf-8', errors='replace').strip()
                                if PORT not in banners:
                                        banners[PORT] = banner
                        except Exception as e:
                                pass
                        finally:
                                s.close()

def tcp_scan_port(HOST, PORT):
        global open_ports_by_host
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timing_profile["timeout"])
        try:
                s.connect((HOST,PORT))
                open_ports_by_host[HOST].append(PORT)
        except:
                pass

def initial_port_find():
        global open_ports_by_host, scanned_ports
        for HOST in sorted(valid_hosts):
                printed_host = hostname_map.get(HOST, HOST)
                open_ports_by_host[HOST] = []
                print(f"\nExecuting initial scan on host {printed_host}.")
                with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                        for PORT in scanned_ports:
                                executor.submit(tcp_scan_port, HOST, PORT)

def run():
    global services, valid_hosts
    initial_scan()
    initialize_ports()
    initial_port_find()
    services = load_services()
    for HOST in valid_hosts:
        printed_host = hostname_map.get(HOST, HOST)
        print(f"\nExecuting banner grab scan on host {printed_host}.")
        banners.clear()
        with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                for PORT in open_ports_by_host[HOST]:
                        executor.submit(grab_banner, HOST, PORT)
        print(f"\n========================================")
        print(f"Completed banner on host: {printed_host}")
        print(f"========================================\n")
        keys = list(banners.keys())
        print(f"Banners found on ports: {sorted(keys)} \n")
        for PORT in sorted(banners):
                service_name = services["tcp"].get(str(PORT)) or "Unknown"
                print(f"---------------------------------------------------------------")
                print(f"Banner for host {printed_host}, port {PORT} (Service: {service_name}):")
                print(f"---------------------------------------------------------------\n")
                print(banners[PORT])
                print('\n')
                
if __name__ == "__main__":
    run()