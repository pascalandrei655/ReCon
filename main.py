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
mandatory.add_argument("-H", "--host")
mandatory.add_argument("-sS",action="store_true", help="TCP SYN Scan")
mandatory.add_argument("-sU",action="store_true", help="UDP Scan")
mandatory.add_argument("-sF",action="store_true", help="TCP FIN Scan")
mandatory.add_argument("-sT",action="store_true", help="TCP Connect Scan")

optional = parser.add_argument_group("Optional arguments")
optional.add_argument("-t", "--timing")

args = parser.parse_args()

HOST = args.host
synScan = args.sS
udpScan = args.sU
finScan=args.sF
conScan=args.sT
timing = args.timing
open_ports = []
closed_ports = []


def scanPort(HOST, PORT):
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
                                executor.submit(scanPort, HOST, PORT)
        print(f"Open ports: {open_ports}")
else:
        print("not implemented")