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
import scanlib

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

class Tee:
        def __init__(self, console_stream, file_stream):
                self.console_stream = console_stream
                self.file_stream = file_stream
        def write(self, text):
                self.console_stream.write(text)
                self.file_stream.write(text)
        def flush(self):
                self.console_stream.flush()
                self.file_stream.flush()

mandatory = parser.add_argument_group("Mandatory arguments")
mandatory.add_argument("-H", "--host", help="Host to perform the scan on. Eg: 192.168.56.101", required=True)

optional = parser.add_argument_group("Optional arguments")
optional.add_argument("-t", "--timing", help="1 - Stealthy; 2 - Calm; 3 - Normal; 4 - Fast; 5 - Aggressive")
optional.add_argument("-p", "--port", help="Ports to scan. Eg: 80; 21,22,80; 1-1023")
optional.add_argument("-o", "--output", help="Save the contents of the scan to a file. Eg: scan.txt")

args = parser.parse_args()

HOST = args.host
ports = args.port
timing = args.timing
output = args.output

open_ports_by_host = dict()

ctx = scanlib.ScanContext(timing=timing)

portPattern = r'^\d+(-\d+)?(,\d+(-\d+)?)*$'

TIMING_PROFILES = {
        "1": {"timeout": 3.0, "workers": 5},
        "2": {"timeout": 1.5, "workers": 20},
        "3": {"timeout": 1, "workers": 50},
        "4": {"timeout": 0.5, "workers": 100},
        "5": {"timeout": 0.3, "workers": 200}
}


banners = dict()

def initialize_ports():
        global ports, TCP_PORTS, UDP_PORTS
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
                                                ctx.scanned_ports.append(i)
                                else:
                                        ctx.scanned_ports.append(int(part))  
        else:
                ctx.scanned_ports = scanlib.load_ports("data/top_tcp_ports.txt")

def initial_scan():           
        scanlib.parse_hosts(args.host, ctx)
        with ThreadPoolExecutor(max_workers=ctx.timing_profile["workers"]) as executor:
                for HOST in ctx.scanned_hosts:
                        executor.submit(scanlib.host_scan, HOST, ctx)

def grab_banner(HOST, PORT):
        global banners
        if int(PORT) in [443, 8443, 9443]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(ctx.timing_profile["timeout"])
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
                                s.settimeout(ctx.timing_profile["timeout"])
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

def initial_port_find():
        global open_ports_by_host
        for HOST in sorted(ctx.valid_hosts):
                printed_host = ctx.hostname_map.get(HOST, HOST)
                open_ports_by_host[HOST] = []
                print(f"\nExecuting initial scan on host {printed_host}.")
                with ThreadPoolExecutor(max_workers=ctx.timing_profile["workers"]) as executor:
                        for PORT in ctx.scanned_ports:
                                executor.submit(scanlib.tcp_scan_port, HOST, PORT, ctx)
        open_ports_by_host[HOST] = list(ctx.open_ports)

def run():
        global services
        if output:
                file_stream = open(output, "w", encoding="utf-8")
                sys.stdout = Tee(sys.stdout, file_stream)
        try:
                initial_scan()
                initialize_ports()
                initial_port_find()
                services = scanlib.load_services()
                for HOST in ctx.valid_hosts:
                        printed_host = ctx.hostname_map.get(HOST, HOST)
                        print(f"\nExecuting banner grab scan on host {printed_host}.")
                        banners.clear()
                        with ThreadPoolExecutor(max_workers=ctx.timing_profile["workers"]) as executor:
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
        finally:
                if output and file_stream:
                        sys.stdout = sys.stdout.console_stream
                        file_stream.close()

                
if __name__ == "__main__":
    run()