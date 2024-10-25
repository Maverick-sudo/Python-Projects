#!/usr/bin/env python

import scapy.all as scapy
import argparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    unanswered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[1]

    # print(unanswered.summary())

    print("IP\t\t\tMAC Address\n----------------------------")
    for ans in answered:
        print(ans[1].psrc + "\t\t" + ans[1].hwsrc)

 # Create an ArgumentParser instance and define the target argument


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='IP range to scan')

    return parser.parse_args()


options = get_arguments()
target_ip = options.target
scan(target_ip)
