import sys
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
sys.stdin, sys.stdout, sys.stderr = i, o, e

def main():
    pcapFile = rdpcap("SynFloodSample.pcap")
    ip_list=set()
    for pkt in pcapFile:
        ip_list.add(pkt[IP].)