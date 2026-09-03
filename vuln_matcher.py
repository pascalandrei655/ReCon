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
import os
from dotenv import load_dotenv
import requests

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def silent_excepthook(args):
    if "sndrcv" in str(args.thread.name):
        return
    threading.__excepthook__(args)

threading.excepthook = silent_excepthook

parser = argparse.ArgumentParser(
        prog="rematcher",
        description="Pizza made vulnerabilty matcher",
        epilog="Thank you for trying %(prog)s! =P"
)

mandatory = parser.add_argument_group("Mandatory arguments")
mandatory.add_argument("-H", "--host", help="Host to perform the scan on. Eg: 192.168.56.101", required=True)

optional = parser.add_argument_group("Optional arguments")
optional.add_argument("-t", "--timing", help="1 - Stealthy; 2 - Calm; 3 - Normal; 4 - Fast; 5 - Aggressive")
optional.add_argument("-p", "--port", help="Ports to scan. Eg: 80; 21,22,80; 1-1023")
optional.add_argument("-c", "--vuln-count", help="Number of vulnerabilities to show. Defaults to 10")

args = parser.parse_args()

HOST = args.host
ports = args.port
timing = args.timing
vuln_count = args.vuln_count
if vuln_count is None:
        vuln_count = 10

valid_hosts = set()
scanned_hosts = []
scanned_ports = []
open_ports_by_host = dict()
hostname_map = dict()
banners = dict()

portPattern = r'^\d+(-\d+)?(,\d+(-\d+)?)*$'


TIMING_PROFILES = {
        "1": {"timeout": 3.0, "workers": 5},
        "2": {"timeout": 1.5, "workers": 20},
        "3": {"timeout": 1, "workers": 50},
        "4": {"timeout": 0.5, "workers": 100},
        "5": {"timeout": 0.3, "workers": 200}
}

def get_timing_profile():
        if timing is None:
                return TIMING_PROFILES["3"]
        if timing not in TIMING_PROFILES:
                print("Timing options: 1 - Stealthy; 2 - Calm; 3 - Normal; 4 - Fast; 5 - Aggressive")
                sys.exit(1)
        return TIMING_PROFILES[timing]

timing_profile = get_timing_profile()

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
                                banners[HOST][PORT] = banner
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
                                        banners[HOST][PORT] = banner
                        except Exception as e:
                                pass
                        finally:
                                s.close()

def store_banners():
       global open_ports_by_host
       for HOST in scanned_hosts:
              banners[HOST] = {}
              printed_host = hostname_map.get(HOST, HOST)
              print(f"\nExecuting banner grab scan on host {printed_host}.")
              with ThreadPoolExecutor(max_workers=timing_profile["workers"]) as executor:
                     for PORT in open_ports_by_host[HOST]:
                            executor.submit(grab_banner, HOST, PORT)

def split_banner_lines(banner):
        return banner.split('\r\n')

def find_server(lines):
        for line in lines:
                if line.lower().startswith("server:"):
                        return line
        return None

def find_backend(lines):
        for line in lines:
                if line.startswith("X-Powered-By:"):
                        return line
        return None

def parse_ssh(banner):
        components = {}
        pattern = r'SSH-\d+\.\d+-([A-Za-z0-9\.-]+?)[\_\-Vv/]([A-Za-z0-9\.-]+)'
        match = re.search(pattern, banner)
        components["Product"] = match.group(1) if match and match.group(1) else "Unknown"
        components["Version"]=match.group(2) if match and match.group(2) else "Unknown"
        return components

def parse_http(banner):
        lines = split_banner_lines(banner)
        server_line = find_server(lines)
        backend_line = find_backend(lines)
        components = {}
        if server_line:
                server_pattern = r'([A-Za-z\-]*)(?:/(\d+\.\d+(?:\.\d+)?))?'
                server_match = re.search(server_pattern, server_line)
                components["Server"] = server_match.group(1) if server_match and server_match.group(1) else "Unknown"
                components["Server_Version"] = server_match.group(2) if server_match and server_match.group(2) else "Unknown"
        else:
                components["Server"] = "Unknown"
                components["Server_Version"] = "Unknown"
        if backend_line:
                backend_pattern = r'([A-Za-z\.\-]+)(?:/(\d+(?:\.\d+)*?)(?:-([A-Za-z0-9\.\-]*))?)?'
                backend_match = re.search(backend_pattern, backend_line)
                components["Language"] = backend_match.group(1) if backend_match and backend_match.group(1) else "Unknown"
                components["Clean_Version"] = backend_match.group(2) if backend_match and backend_match.group(2) else "Unknown"
                components["SO_Version"] = backend_match.group(3) if backend_match and backend_match.group(3) else "Unknown"
        else:
                components["Language"] = "Unknown"
                components["Clean_Version"] = "Unknown"
                components["SO_Version"] = "Unknown"
        return components

def parse_ftp(banner):
        components = {}
        pattern = r'([A-Za-z0-9\.\-]+)\s+v?(\d+(?:\.\d+)+)'
        match = re.search(pattern, banner)
        components["Server"] = match.group(1) if match and match.group(1) else "Unknown"
        components["Version"] = match.group(2) if match and match.group(2) else "Unknown"
        return components

def parse_smtp(banner):
        components = {}
        pattern = r'(?:220[- ]\S+\s+)?(?:ESMTP\s+)?([A-Za-z0-9\.\-_]+?)(?:/|\s+v?|\s*\()(\d+(?:\.[A-Za-z0-9\._\-]+)+)'
        match = re.search(pattern, banner)
        components["Product"] = match.group(1) if match and match.group(1) else "Unknown"
        components["Version"] = match.group(2) if match and match.group(2) else "Unknown"
        return components

def parse_sql(banner):
        components = {}
        pattern = r'(?:([A-Za-z0-9\._\-]+)\s+)?v?(\d+\.\d+\.[0-9a-z]+)'
        match = re.search(pattern, banner)
        components["Product"] = match.group(1) if match and match.group(1) else "mysql"
        components["Version"] = match.group(2) if match and match.group(2) else "Unknown"
        return components

def parse_telnet(banner):
        components = {}
        pattern = r'(?i)\b([A-Za-z0-9\._\-/]+?)\s+(?:v(?:ersion)?[\s/]*|Software,?\s+)?([\d\.]+(?:\([\d\w\.-]+\))?[\w\.-]*)'
        match = re.search(pattern, banner)
        components["Product"] = match.group(1) if match and match.group(2) else "Unknown"
        components["Version"] = match.group(2) if match and match.group(1) else "Unknown"
        return components

def parse_smb(banner):
        components = {}
        pattern = r'(?i)\b(Samba)\b\s+v?(\d+(?:\.\d+)+[a-z]?)(?:[-_\s\(]+([A-Za-z0-9.]+)\)?)?'
        match = re.search(pattern, banner)
        components["Product"] = "samba"
        components["Version"] = match.group(1) if match and match.group(1) else "Unknown"
        components["OS"] = match.group(2) if match and match.group(2) else "Unknown"
        return components

def parse_banner(port, banner):
        if port == 22:
                return parse_ssh(banner)
        elif port in [80, 8080, 8000, 8888, 443, 8443, 9443]:
                return parse_http(banner)
        elif port == 21:
                return parse_ftp(banner)
        elif port == 25:
                return parse_smtp(banner)
        elif port == 3306:
                return parse_sql(banner)
        elif port == 23:
                return parse_telnet(banner)
        elif port in [139, 445]:
                return parse_smb(banner)
        else:
                return {"Raw": banner}

def load_cpe_mapping():
        with open('data/cpe_mapping.json','r') as f:
                mapping = json.load(f)
        return mapping

def build_cpe(product, version, language, part="a"):
        product = product.strip().lower()
        version = version.strip().lower()
        language = language.strip().lower()
        if product == "unknown" or not product:
                print("[CRITICAL] Product could not be determined from captured banner. CPE is not constructable. Aborting.")
                return False
        if version == "unknown" or not version:
                print("\nVersion could not be determined from captured banner. Showing general vulnerabilities of specified product")
                version = "*"
        if language == "unknown" or not language:
                print("\n[MINOR] Language could not be determined")
        key = product
        mapping = load_cpe_mapping()
        entry = mapping.get(key)
        if entry is None:
                print("[CRITICAL] Product not found in database. You can add it to data/cpe_mapping.json")
                return False
        cpe_string = f"cpe:2.3:{part}:{entry['vendor']}:{entry['product']}:{version}:*:*:*:*:*:*:*"
        return cpe_string


def fetch_nvd_data(cpe_string):
        if not cpe_string:
                return None
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cpeName": cpe_string}
        headers = {}
        if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY
        try:
                response = requests.get(url, params=params, headers=headers, timeout=10)
                if response.status_code == 200:
                        data = response.json()
                        return data
                else:
                        return None
        except requests.RequestException as e:
                print(f"Eroare: {e}")
                return None

def extract_vulnerabilities(data):
        vulnerabilities = []
        for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "-")

                description = cve_data["descriptions"][0]["value"]

                score = 0.0
                severity = "UNKNOWN"

                metrics = cve_data.get("metrics",{})
                if "cvssMetricV31" in metrics:
                        metric = metrics["cvssMetricV31"][0]
                        score = metric.get("cvssData", {}).get("baseScore", 0.0)
                        severity = metric.get("cvssData", {}).get("baseSeverity", "N/A")
                elif "cvssMetricV30" in metrics:
                        metric = metrics["cvssMetricV30"][0]
                        score = metric.get("cvssData", {}).get("baseScore", 0.0)
                        severity = metric.get("cvssData", {}).get("baseSeverity", "N/A")
                elif "cvssMetricV2" in metrics:
                        metric = metrics["cvssMetricV2"][0]
                        score = metric.get("cvssData", {}).get("baseScore", 0.0)
                        severity = metric.get("baseSeverity", "N/A")

                vulnerabilities.append({
                        "cve_id": cve_id,
                        "description": description,
                        "severity": severity,
                        "baseScore": score
                })

        vulnerabilities.sort(key=lambda x: x["baseScore"], reverse=True)
        return vulnerabilities


def display_vulnerabilities(data):
        print(f'\nA total of {data["totalResults"]} have been found. Showing top {vuln_count} vulnerabilities, sorted by CVSS rating')
        vulnerabilities = extract_vulnerabilities(data)
        for vuln in vulnerabilities[:vuln_count]:
                print(f'\n==========================================================================')
                print(f'Vulnerability: {vuln["cve_id"]} (https://www.cve.org/CVERecord?id={vuln["cve_id"]})')
                print(f'Severity: {vuln["severity"]} (CVSS Score: {vuln["baseScore"]})')
                print("\nDescription:")
                print(vuln["description"])

def run():
        banner = "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"
        port = 22
        components = parse_banner(port, banner)
        cpe_string = build_cpe(components["Product"],components["Version"],components.get("Language","*"),"a")
        print(cpe_string)
        data = fetch_nvd_data(cpe_string)
        display_vulnerabilities(data)

if __name__ == "__main__":
    run()
