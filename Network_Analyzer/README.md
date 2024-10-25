
# Network Traffic Analyzer
# Suspicious Packet Detection

## Description
This Python script is designed to monitor network traffic and detect suspicious activities like data exfiltration, SYN scanning, FIN scanning, DNS poisoning, and ARP spoofing. It uses the Scapy library for packet sniffing and manipulation.

The script provides real-time monitoring of all inbound and outbound network packets. It logs the source and destination IP addresses, as well as the protocol used for each packet. This information is then used to identify patterns that could indicate malicious activity.

In addition to logging suspicious activities, alerts are sent via email and Telegram when a potential threat is detected.

## Features
- Packet-level visibility
- Real-time monitoring of network traffic
- Detection of various types of network threats
- Alerts via email and Telegram
- Logging of suspicious activities

## Usage
Please replace placeholders in the code with your actual data:
- `'youremail@gmail.com'`
- `'yourpassword'`
- `'recipientemail@gmail.com'`
- `'your_bot_token'`
- `'your_chat_id'`

Also, define your desired threshold value for outbound traffic monitoring by replacing `OUTBOUND_THRESHOLD`.

## Warning on Privacy Laws and Policies
This tool is intended for use in environments where you have been granted explicit permission to monitor network traffic. Unauthorized use of this tool for packet sniffing may violate privacy laws, regulations, or policies. 

It is essential to understand that the misuse of tools like these can lead to severe penalties, including legal action. Always ensure you have obtained proper authorization before monitoring network traffic. If you are unsure about the legality of your actions, please consult with a legal professional or your organization's policy on network monitoring.

## Disclaimer
This tool is provided for educational purposes only. The author is not responsible for any damage caused by the misuse of this tool. Always use responsibly and within the confines of the law.
