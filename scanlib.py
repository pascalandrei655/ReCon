import socket
from scapy.all import IP, TCP, sr1, send, ICMP, arping
import ipaddress
import json
import sys
from data.payloads import udp_payloads
import threading

TIMING_PROFILES = {
        "1": {"timeout": 3.0, "workers": 5},
        "2": {"timeout": 1.5, "workers": 20},
        "3": {"timeout": 1, "workers": 50},
        "4": {"timeout": 0.5, "workers": 100},
        "5": {"timeout": 0.3, "workers": 200}
}

class ScanContext:
    def __init__(self, timing=None):
        self.timing_profile = get_timing_profile(timing)
        self.scanned_hosts = []
        self.valid_hosts = set()
        self.hostname_map = {}
        self.scanned_ports = []
        self.open_ports = []
        self.openFiltered_ports = []
        self.closed_ports = []

        self._lock = threading.Lock()

    def add_open(self, port):
        with self._lock:
            self.open_ports.append(port)
    
    def add_closed(self, port):
        with self._lock:
            self.closed_ports.append(port)
    
    def add_open_filtered(self, port):
        with self._lock:
            self.openFiltered_ports.append(port)    


def parse_hosts(HOST, ctx):
        parts = HOST.split(',')
        for part in parts:
                if(is_hostname(part)):
                        try:
                                ctx.hostname_map[socket.gethostbyname(part)] = part
                                part = socket.gethostbyname(part)                     
                                try:
                                        arping(part, timeout=ctx.timing_profile["timeout"], verbose=0)
                                        ip = ipaddress.ip_address(part)
                                        ctx.scanned_hosts.append(str(ip))
                                except ValueError:
                                        print(f"Invalid IP address:{part}")
                                        return      
                        except socket.gaierror:
                                print(f"Could not resolve hostname: {part}")
                                continue
                elif '-' in part:
                        try:
                                arping(part, timeout=ctx.timing_profile["timeout"], verbose=0)
                                start_ip = ipaddress.ip_address(part.split('-')[0])
                                end_ip = ipaddress.ip_address(part.split('-')[1])
                                if(start_ip > end_ip):
                                        print("Invalid IP Range")
                                        return
                                current_ip = start_ip
                                while current_ip <= end_ip:
                                        ctx.scanned_hosts.append(str(current_ip))
                                        current_ip = current_ip + 1
                        except ValueError:
                                print("Invalid IP format")
                                return
                elif '/' in part:
                        try:
                                arping(part, timeout=ctx.timing_profile["timeout"], verbose=0)
                                net = ipaddress.ip_network(part, strict=False)
                                for ip in net.hosts():
                                        ctx.scanned_hosts.append(str(ip))
                        except ValueError:
                                print("Invalid CIDR format")
                                return
                else:
                        try:
                                arping(part, timeout=ctx.timing_profile["timeout"], verbose=0)
                                ip = ipaddress.ip_address(part)
                                ctx.scanned_hosts.append(str(ip))
                        except ValueError:
                                print(f"Invalid IP address:{part}")
                                return

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

def get_timing_profile(timing):
        if timing is None:
                return TIMING_PROFILES["3"]
        if timing not in TIMING_PROFILES:
                print("Timing options: 1 - Stealthy; 2 - Calm; 3 - Normal; 4 - Fast; 5 - Aggressive")
                sys.exit(1)
        return TIMING_PROFILES[timing]

def tcp_scan_port(HOST, PORT, ctx):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(ctx.timing_profile["timeout"])
        try:
                s.connect((HOST,PORT))
                ctx.add_open(PORT)
        except:
                ctx.add_closed(PORT)   

def udp_scan_port(HOST, PORT, ctx):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(ctx.timing_profile["timeout"])
        try:
                payload = udp_payloads.get(PORT,b"")
                s.connect((HOST,PORT))
                s.send(payload)
                data = s.recv(1024)
                ctx.add_open(PORT)
        except ConnectionRefusedError:
                ctx.add_closed(PORT) 
        except socket.timeout:
                ctx.add_open_filtered(PORT)
        finally:
                s.close()

def syn_scan_port(HOST, PORT, ctx):
        try:
                syn_packet = IP(dst=HOST) / TCP(dport=PORT, flags='S')
                response = sr1(syn_packet, timeout=ctx.timing_profile["timeout"], verbose=0)
                if response is None:
                        pass
                elif response.haslayer(TCP):
                        if response[TCP].flags == 'SA':
                                ctx.add_open(PORT)
                                rst_packet = IP(dst=HOST) / TCP(dport=PORT, flags='R')
                                send(rst_packet, verbose=0)
                        elif response[TCP].flags == 'R':
                                ctx.add_closed(PORT) 
                        else:
                                ctx.add_closed(PORT) 
        except Exception as e:
                pass
    
def fin_scan_port(HOST, PORT, ctx):
        try:
                fin_packet = IP(dst=HOST) / TCP(dport=PORT, flags='F')
                response = sr1(fin_packet, timeout=ctx.timing_profile["timeout"], verbose=0)
                if response is None:
                        ctx.add_open(PORT)
                elif(response.haslayer(TCP)):
                        if(response.getlayer(TCP).flags == 0x14):
                                ctx.add_closed(PORT) 
                elif(response.haslayer(ICMP)):
                        if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                ctx.add_open_filtered(PORT)
        except Exception as e:
                pass
                                       
def host_scan(HOST, ctx):
        try:
                packet = IP(dst=HOST) / ICMP()
                response = sr1(packet, timeout=ctx.timing_profile["timeout"], verbose=0)
                if response and response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
                        ctx.valid_hosts.add(HOST)
                        return
                packet = IP(dst=HOST) / TCP(dport=443, flags='S')
                response = sr1(packet, timeout=ctx.timing_profile["timeout"], verbose=0)
                if(response and response.haslayer(TCP) and response[TCP].flags == 'SA'):
                        ctx.valid_hosts.add(HOST)
                        return
                packet = IP(dst=HOST) / TCP(dport=80, flags='A')
                response = sr1(packet, timeout=ctx.timing_profile["timeout"], verbose=0)
                if(response and response.haslayer(TCP) and response[TCP].flags == 'R'):
                        ctx.valid_hosts.add(HOST)
                        return
                packet = IP(dst=HOST) / ICMP(type=13)
                response = sr1(packet, timeout=ctx.timing_profile["timeout"], verbose=0)
                if(response and response.haslayer(ICMP) and response.getlayer(ICMP).type == 14):
                        ctx.valid_hosts.add(HOST)
                        return
        except Exception as e:
                pass