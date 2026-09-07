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
import scanlib

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
mandatory.add_argument("-H", "--host", help="Host to perform the scan on. Eg: 192.168.56.101",required=True)
mandatory.add_argument("-sS",action="store_true", help="TCP SYN Scan")
mandatory.add_argument("-sU",action="store_true", help="UDP Scan")
mandatory.add_argument("-sF",action="store_true", help="TCP FIN Scan")
mandatory.add_argument("-sT",action="store_true", help="TCP Connect Scan")
mandatory.add_argument("-sH",action="store_true", help="Host Discovery Scan")

optional = parser.add_argument_group("Optional arguments")
optional.add_argument("-t", "--timing", help="1 - Stealthy; 2 - Calm; 3 - Normal; 4 - Fast; 5 - Aggressive")
optional.add_argument("-p", "--port", help="Ports to scan. Eg: 80; 21,22,80; 1-1023")
optional.add_argument("-o", "--output", help="Save the contents of the scan to a file. Eg: scan.txt")

args = parser.parse_args()

HOST = args.host
synScan = args.sS
udpScan = args.sU
finScan=args.sF
conScan=args.sT
hostScan = args.sH
timing = args.timing
ports = args.port
output =  args.output

ctx = scanlib.ScanContext(timing=timing)

TCP_PORTS = []
UDP_PORTS = []

portPattern = r'^\d+(-\d+)?(,\d+(-\d+)?)*$'

TIMING_PROFILES = {
        "1": {"timeout": 3.0, "workers": 5},
        "2": {"timeout": 1.5, "workers": 20},
        "3": {"timeout": 1, "workers": 50},
        "4": {"timeout": 0.5, "workers": 100},
        "5": {"timeout": 0.3, "workers": 200}
}


def initial_scan():           
        scanlib.parse_hosts(args.host, ctx)
        if((args.sT or args.sU or args.sF or args.sS) and args.sH == False):
                with ThreadPoolExecutor(max_workers=ctx.timing_profile["workers"]) as executor:
                        for HOST in ctx.scanned_hosts:
                                executor.submit(scanlib.host_scan, HOST, ctx)

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
                TCP_PORTS = scanlib.load_ports('data/top_tcp_ports.txt')
                UDP_PORTS = scanlib.load_ports('data/top_udp_ports.txt')        

def execute_con_scan():
        if(synScan or udpScan or finScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        ctx.scanned_ports = TCP_PORTS
                for HOST in sorted(ctx.valid_hosts):
                        ctx.open_ports.clear()
                        printed_host = ctx.hostname_map.get(HOST, HOST)
                        print(f"\nExecuting TCP Connect Scan on host {printed_host}: ")
                        with ThreadPoolExecutor(max_workers=ctx.timing_profile["workers"]) as executor:
                                for PORT in ctx.scanned_ports:
                                        executor.submit(scanlib.tcp_scan_port, HOST, PORT, ctx)
                        print(f"\n----------------------------------------------")
                        print(f"Port       -      Status      -       Protocol")
                        print(f"----------------------------------------------")
                        for port in ctx.open_ports:
                                print(f"{port}       -       Open       -       {services["tcp"][str(port)]}")

def execute_udp_scan():
        if(synScan or conScan or finScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        ctx.scanned_ports = UDP_PORTS
                for HOST in sorted(ctx.valid_hosts):
                        ctx.open_ports.clear()
                        printed_host = ctx.hostname_map.get(HOST, HOST)
                        print(f"Executing UDP Scan on {printed_host}: ")
                        with ThreadPoolExecutor(max_workers=ctx.timing_profile["workers"]) as executor:
                                for PORT in ctx.scanned_ports:
                                        executor.submit(scanlib.udp_scan_port, HOST, PORT, ctx)
                        ctx.open_ports = list(set(ctx.open_ports))
                        closed_ports = list(set(closed_ports))
                        openFiltered_ports = list(set(openFiltered_ports))
                        print(f"\n----------------------------------------------")
                        print(f"Port       -      Status      -       Protocol")
                        print(f"----------------------------------------------")
                        for port in sorted(ctx.open_ports):
                                print(f"{port}       -       Open       -       {services["udp"][str(port)]}")
                        for port in sorted(openFiltered_ports):
                                print(f"{port}       -    Open/Filtered    -       {services["udp"][str(port)]}")

def execute_syn_scan():
        if(conScan or udpScan or finScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        ctx.scanned_ports = TCP_PORTS
                for HOST in sorted(ctx.valid_hosts):
                        ctx.open_ports.clear()
                        printed_host = ctx.hostname_map.get(HOST, HOST)
                        print(f"Executing TCP Syn Scan on {printed_host}: ")
                        with ThreadPoolExecutor(max_workers=ctx.timing_profile["workers"]) as executor:
                                for PORT in ctx.scanned_ports:
                                        executor.submit(scanlib.syn_scan_port, HOST, PORT, ctx)
                        print(f"\n----------------------------------------------")
                        print(f"Port       -      Status      -       Protocol")
                        print(f"----------------------------------------------")
                        for port in sorted(ctx.open_ports):
                                print(f"{port}       -       Open       -       {services["tcp"][str(port)]}")

def execute_fin_scan():
        if(conScan or udpScan or synScan or hostScan):
                print("Please choose only one scan type")
        else:
                if(ports==None):
                        ctx.scanned_ports = TCP_PORTS
                for HOST in sorted(ctx.valid_hosts):
                        ctx.open_ports.clear()
                        printed_host = ctx.hostname_map.get(HOST, HOST)
                        print(f"Executing TCP Fin Scan on {printed_host}: ")
                        with ThreadPoolExecutor(max_workers=ctx.timing_profile["workers"]) as executor:
                                for PORT in ctx.scanned_ports:
                                        executor.submit(scanlib.fin_scan_port, HOST, PORT, ctx)
                        print(f"\n----------------------------------------------")
                        print(f"Port       -      Status      -       Protocol")
                        print(f"----------------------------------------------")
                        for port in sorted(ctx.open_ports):
                                print(f"{port}       -       Open       -       {services["tcp"][str(port)]}")

def execute_host_scan():
        if(conScan or udpScan or synScan or finScan):
                print("Please choose only one scan type")
        else:
                printed_host = ctx.hostname_map.get(args.host, args.host)
                print(f"Executing Host Discovery Scan on {printed_host}")
                with ThreadPoolExecutor(max_workers=ctx.timing_profile["workers"]) as executor:
                        for HOST in ctx.scanned_hosts:
                                executor.submit(scanlib.host_scan, HOST, ctx)
                print(f"\n-------------------------------------")
                print(f"Host                 -     Status")
                print(f"-------------------------------------")
                for host in sorted(ctx.valid_hosts):
                        print(f"{host}       -      Open")
                print("\n")


def run():
        global services
        if output:
                file_stream = open(output, "w", encoding="utf-8")
                sys.stdout = Tee(sys.stdout, file_stream)
        try:
                initial_scan()
                initialize_ports()
                services = scanlib.load_services()
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
        finally:
                if output and file_stream:
                        sys.stdout = sys.stdout.console_stream
                        file_stream.close()

if __name__ == "__main__":
    run()