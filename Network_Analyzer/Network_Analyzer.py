from ipaddress import ip_network, ip_address
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import requests
import logging
import os
from scapy.all import *
from scapy.layers.inet import checksum
from collections import defaultdict

# Initialize dictionaries for host and protocol stats
host_stats = defaultdict(int)
protocol_stats = defaultdict(int)

SMTP_SERVER = 'smtp.gmail.com: 587'
SMTP_USERNAME = 'youremail@gmail.com'
SMTP_PASSWORD = 'yourpassword'
RECIPIENT_EMAIL = 'recipientemail@gmail.com'

bot_token = 'your_bot_token'
bot_chatID = 'your_chat_id'

cidr_address = '192.168.0.0/16'

OUTBOUND_THRESHOLD = 'Set your Outbound Threshold'

def increment_dict_count(dict_obj, key):
    # Increment the count in the dictionary for the given key
    if key not in dict_obj:
        dict_obj[key] = 0
    dict_obj[key] += 1


def setup_logging():
    script_path = os.path.dirname(os.path.realpath(__file__))

    # Create a logger
    logger = logging.getLogger('Suspicious_Packet_Detection')
    logger.setLevel(logging.INFO)

    # Create a file handler
    handler = logging.FileHandler(os.path.join(
        script_path, 'suspicious_packets.log'))
    handler.setLevel(logging.INFO)

    # Create a logging format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(handler)

    return logger


logger = setup_logging()


def packet_handler(packet):
    try:
        # Check if the packet has been altered.
        if packet.haslayer("IP"):
            ip_layer = packet.getlayer("IP")
            check_ip_packet(ip_layer)

        if packet.haslayer("TCP"):
            tcp_layer = packet.getlayer("TCP")
            check_tcp_flags(tcp_layer)

        if packet.haslayer("DNS"):
            dns_layer = packet.getlayer("DNS")
            check_dns_poisoning(dns_layer)

        if packet.haslayer("ARP"):
            arp_layer = packet.getlayer("ARP")
            check_arp_spoofing(arp_layer)
    except Exception as e:
        logger.error(f"Error processing packet: {e}")


def process_packet(packet):
    try:
        # Packet-level visibility
        print(
            f"Source: {packet[IP].src}, Destination: {packet[IP].dst}, Protocol: {packet[IP].proto}")

        # Update host stats
        increment_dict_count(host_stats, packet[IP].src)
        increment_dict_count(host_stats, packet[IP].dst)

        # Update protocol stats
        increment_dict_count(protocol_stats, packet[IP].proto)
    except Exception as e:
        logger.error(f"Error processing packet: {e}")


def check_ip_packet(ip_layer):
    # Initialize dictionaries for packet and protocol counts
    packet_counts = defaultdict(int)
    protocol_counts = defaultdict(int)

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto = ip_layer.proto

    # Count the packets from each IP.
    increment_dict_count(packet_counts, src_ip)

    # Count the packets for each protocol.
    increment_dict_count(protocol_counts, proto)

    # Monitor for unusual outbound traffic.
    if is_external(dst_ip) and packet_counts[src_ip] > OUTBOUND_THRESHOLD:
        print(f"Possible data exfiltration from {src_ip} to {dst_ip}")
        log_suspicious_packet(ip_layer)


def check_tcp_flags(packet):
    # Check if it is a TCP packet
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)

        # Calculate checksum
        tcp_checksum = checksum(bytes(tcp_layer))

        # Verify checksum
        if tcp_layer.chksum != tcp_checksum:
            print("Packet corrupted during transmission:", packet.summary())
            log_suspicious_packet(packet)

        # Check for SYN scanning
        elif tcp_layer.flags == 'S':
            print("Possible SYN scan detected:", packet.summary())
            log_suspicious_packet(packet)

        # Check for FIN scanning
        elif tcp_layer.flags == 'F':
            print("Possible FIN scan detected:", packet.summary())
            log_suspicious_packet(packet)

        else:
            print("TCP packet is normal")


def check_dns_poisoning(dns_layer):
    # If the DNS response doesn't match the request, it might be DNS poisoning.
    if dns_layer.qr == 1 and dns_layer.haslayer(DNSQR):
        query = dns_layer.getlayer(DNSQR).qname
        if query != dns_layer.ancount:
            print("Possible DNS poisoning detected:", dns_layer.summary())
            log_suspicious_packet(dns_layer)


def check_arp_spoofing(arp_layer):
    # If the ARP reply doesn't match the request, it might be ARP spoofing.
    if arp_layer.op == 2:  # Is-At (reply)
        req_plen = arp_layer.plen

        # Calculate total length of the ARP packet
        rep_tlen = len(arp_layer)

        if req_plen != rep_tlen:
            print("Possible ARP spoofing detected:", arp_layer.summary())
            log_suspicious_packet(arp_layer)


def is_external(ip):
    # Define the range of internal IP addresses
    internal_ip = ip_network(cidr_address)

    # Return True if the IP address is not in the defined range
    return not ip_address(ip) in internal_ip


def send_email_alert(subject, message):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = RECIPIENT_EMAIL
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, RECIPIENT_EMAIL, msg.as_string())
        server.quit()

    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")


def send_telegram_alert(text):
    send_text = f'https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={bot_chatID}&parse_mode=Markdown&text={text}'

    response = requests.get(send_text)

    return response.json()


def log_suspicious_packet(packet):
    logger.info(f"Suspicious packet detected: {packet.summary()}")
    send_telegram_alert(f"Suspicious packet detected: {packet.summary()}")
    send_email_alert(f"Suspicious packet detected: {packet.summary()}")


sniff(prn=packet_handler, store=False)

# Start sniffing packets
sniff(prn=process_packet, store=False)

# Print host stats
for host, count in host_stats.items():
    print(f"{host}: {count} packets")

# Print protocol stats
for protocol, count in protocol_stats.items():
    print(f"Protocol {protocol}: {count} packets")
