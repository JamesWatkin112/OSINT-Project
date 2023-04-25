import tkinter
import customtkinter
import requests
import json

import socket

import zlib
from base64 import b64decode

customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("green")

class ApiKeyError(Exception):
    def __init__(self, program):
        self.message = f'Api Key Error for program: {program}'
        super().__init__(self.message)

class osint(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        # Define parameters of the window
        self.title("Python 30061640")
        self.geometry(f'{610}x{580}')

        self.firstClick = True
        self.VirusTotal_API, self.VirusTotal_URL = f'{self.decrypt("NWM1NTg2MjFmYzZjODU1ZmYzNmZlNTg1YTJlNjI1MjZiNWFkY2VmZTRlNWI0MjRmODJlYjIwNGJkZWE4YjdiOQ==")}', 'https://www.virustotal.com/api/v3/domains/'
        self.BufferOverrun_API, self.BufferOverrun_URL = f'{self.decrypt("TTVzYTU0MmtjeWFCVEtTTHBZOXhPMTg2Tkc2VTVIUEozUGp3ZDBQOA==")}', 'https://tls.bufferover.run/dns?q='

        self.sidebar = customtkinter.CTkFrame(self, width=170, height = 580, corner_radius=0)
        self.sidebar.place(x=0, y=0)

        self.title = customtkinter.CTkLabel(self.sidebar, text="OSINT Project", font=customtkinter.CTkFont(size=24, weight="bold"))
        self.title.place(x=3, y=10)

        self.domain_button = customtkinter.CTkButton(self.sidebar, command=self.domain_report, text="Enter domain name")
        self.domain_button.place(x=15, y=60)

        self.IP_button = customtkinter.CTkButton(self.sidebar, command=self.IP_report, text="Enter IP")
        self.IP_button.place(x=15, y=100)

        self.settings_button = customtkinter.CTkButton(self.sidebar, command=self.settings, text="Settings")
        self.settings_button.place(x=15, y=140)

        self.quit_button = customtkinter.CTkButton(self.sidebar, command=self.quit, text="Quit")
        self.quit_button.place(x=15, y=180)

    def settings(self):
        if self.firstClick:
            self.settings_frame = customtkinter.CTkFrame(self, width=400, height=290)
            self.settings_frame.place(x=190, y=15)
            self.firstClick = False
        else:
            if self.settings_frame.winfo_exists():
                self.settings_frame.destroy()
            else:
                self.settings_frame = customtkinter.CTkFrame(self, width=400, height=290)
                self.settings_frame.place(x=190, y=15)

    def quit(self):
        exit()
    
    def domain_report(self):
        print(self.VirusTotal('southwales.ac.uk'))

    def IP_report(self):
        pass

    def Port_scanner(self, IP):
        dialog = customtkinter.CTkInputDialog(text='Enter lower port range')
        lower_range = int(dialog.get_input())
        dialog = customtkinter.CTkInputDialog(text='Enter upper port range')
        upper_range = int(dialog.get_input())
        if lower_range > upper_range:
            upper_range, lower_range = lower_range, upper_range
        open_ports = []
        for port in range(lower_range, upper_range+1):
            res = self.scan_port(IP, port)
            if res != None:
                open_ports.append(port)
        return open_ports
            
    
    def scan_port(self, IP, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((IP, port))
            if result == 0:
                return port
        except:
            pass
        finally:
            # Close the socket
            socket.close()

    def VirusTotal(self, domain):
        headers = {'accept': 'application/json',
                    'x-apikey': self.VirusTotal_API}
        response = requests.get(f'{self.VirusTotal_URL}{domain}', headers = headers)
        if response.status_code == 200:
            text = response.text
            json_file = json.loads(text)
            ratings = json_file['data']['attributes']['last_analysis_stats']
            DNS_records = json_file['data']['attributes']['last_dns_records']

            return ratings, DNS_records
        else:
            raise ApiKeyError('VirusTotal')
    
    def BufferOverrun(self, domain):
        headers = {'x-api-key': self.BufferOverrun_API}
        response = requests.get(f'{self.BufferOverrun_URL}{domain}', headers = headers)
        if response.status_code == 200:
            text = response.text
            json_file = json.loads(text)
            IPv4_certificates = json_file['Results']

            return IPv4_certificates
        else:
            raise ApiKeyError('BufferOverrun')
    
    def IpInfo(address):
        response = requests.get(f'https://ipinfo.io/{address}/geo')
        if response.status_code == 200:
            text = response.text
            json_file = json.loads(text)
            hostname, city, region, location = json_file['hostname'], json_file['city'], json_file['region'], json_file['loc']
            return (hostname, city, region, location)
        else:
            raise ApiKeyError('IpInfo')
    
    def decrypt(self, input):
        string = bytes(input, 'utf-8')
        return_value = b64decode(string).decode()
        return return_value

Program = osint()
Program.mainloop()