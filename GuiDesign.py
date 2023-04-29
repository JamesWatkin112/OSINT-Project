import tkinter
import customtkinter
import requests
import json
import os

import socket
import re

import zlib
from base64 import b64decode
#-------------------------------------------------------------------------------------------------#

# Set appearance
customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("green")

class ApiKeyError(Exception):
    '''
    Custom Exception made to show when there is an API error, and what program it is associated with 
    '''
    def __init__(self, program):
        self.message = f'Api Key Error for program: {program}'
        super().__init__(self.message)

class osint(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        # Define parameters of the window
        self.title("Python 30061640")
        self.geometry(f'{610}x{320}')

        self.firstClick = True
        # Define API keys with respective URLS
        self.VirusTotal_API, self.VirusTotal_URL = f'{self.decrypt("NWM1NTg2MjFmYzZjODU1ZmYzNmZlNTg1YTJlNjI1MjZiNWFkY2VmZTRlNWI0MjRmODJlYjIwNGJkZWE4YjdiOQ==")}', 'https://www.virustotal.com/api/v3/domains/'
        self.BufferOverrun_API, self.BufferOverrun_URL = f'{self.decrypt("TTVzYTU0MmtjeWFCVEtTTHBZOXhPMTg2Tkc2VTVIUEozUGp3ZDBQOA==")}', 'https://tls.bufferover.run/dns?q='

        # Setup widgets on screen
        self.sidebar = customtkinter.CTkFrame(self, width=170, height = 320, corner_radius=0)
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

        self.VirusTotal_toggle = customtkinter.BooleanVar(self, False)
        self.Domain_toggle = customtkinter.BooleanVar(self, False)
        self.SubBrute_toggle = customtkinter.BooleanVar(self, False)
        self.BufferOverrun_toggle = customtkinter.BooleanVar(self, False)
        self.IP_toggle = customtkinter.BooleanVar(self, False)
        self.IPInfo_toggle = customtkinter.BooleanVar(self, False)
        self.Ports_toggle = customtkinter.BooleanVar(self, False)

        self.debug = False
        
        # Main dictionary for all module toggles
        self.Toggles = {'Domain':
            {'Master': self.Domain_toggle,
             'VirusTotal': self.VirusTotal_toggle,
             'SubBrute': self.SubBrute_toggle,
             'BufferOverrun': self.BufferOverrun_toggle},
           'IP':
            {'Master': self.IP_toggle,
             'IpInfo': self.IPInfo_toggle,
             'Ports' : self.Ports_toggle}
          }

    def settings(self):
        if self.firstClick:
            # If settings button has not been clicked before, run this
            self.settings_frame = customtkinter.CTkFrame(self, width=400, height=290)
            self.settings_frame.place(x=190, y=15)
            self.firstClick = False
            
            self.domain_label = customtkinter.CTkLabel(self.settings_frame, text='Domain', font=customtkinter.CTkFont(size=24, weight="bold"))
            self.domain_label.place(x= 35, y=20)
            self.domain_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.Domain_toggle, onvalue=True, offvalue=False, text='Master')
            self.domain_button.place(x=35, y= 70)
            self.VirusTotal_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.VirusTotal_toggle, onvalue=True, offvalue=False, text='VirusTotal')
            self.VirusTotal_button.place(x=35, y= 120)
            self.SubBrute_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.SubBrute_toggle, onvalue=True, offvalue=False, text='SubBrute')
            self.SubBrute_button.place(x=35, y= 170)
            self.Buffer_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.BufferOverrun_toggle, onvalue=True, offvalue=False, text='BufferOverrun')
            self.Buffer_button.place(x=35, y= 220)

            self.IP_label = customtkinter.CTkLabel(self.settings_frame, text='IP Address', font=customtkinter.CTkFont(size=24, weight="bold"))
            self.IP_label.place(x= 240, y=20)
            self.IP_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.IP_toggle, onvalue=True, offvalue=False, text='Master')
            self.IP_button.place(x=240, y= 70)
            self.ports_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.Ports_toggle, onvalue=True, offvalue=False, text='Port Scanner')
            self.ports_button.place(x=240, y= 120)
            self.IPInfo_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.IPInfo_toggle, onvalue=True, offvalue=False, text='IpInfo')
            self.IPInfo_button.place(x=240, y= 170)
        else:
            if self.settings_frame.winfo_exists():
                # If window is open on screen when button is pressed
                self.settings_frame.destroy()
            else:
                # If it's not the first click and the window is not shown on screen
                self.settings_frame = customtkinter.CTkFrame(self, width=400, height=290)
                self.settings_frame.place(x=190, y=15)
                
                self.domain_label = customtkinter.CTkLabel(self.settings_frame, text='Domain', font=customtkinter.CTkFont(size=24, weight="bold"))
                self.domain_label.place(x= 35, y=20)
                self.domain_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.Domain_toggle, onvalue=True, offvalue=False, text='Master')
                self.domain_button.place(x=35, y= 70)
                self.VirusTotal_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.VirusTotal_toggle, onvalue=True, offvalue=False, text='VirusTotal')
                self.VirusTotal_button.place(x=35, y= 120)
                self.SubBrute_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.SubBrute_toggle, onvalue=True, offvalue=False, text='SubBrute')
                self.SubBrute_button.place(x=35, y= 170)
                self.Buffer_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.BufferOverrun_toggle, onvalue=True, offvalue=False, text='BufferOverrun')
                self.Buffer_button.place(x=35, y= 220)

                self.IP_label = customtkinter.CTkLabel(self.settings_frame, text='IP Address', font=customtkinter.CTkFont(size=24, weight="bold"))
                self.IP_label.place(x= 240, y=20)
                self.IP_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.IP_toggle, onvalue=True, offvalue=False, text='Master')
                self.IP_button.place(x=240, y= 70)
                self.ports_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.Ports_toggle, onvalue=True, offvalue=False, text='Port Scanner')
                self.ports_button.place(x=240, y= 120)
                self.IPInfo_button = customtkinter.CTkCheckBox(self.settings_frame, variable=self.IPInfo_toggle, onvalue=True, offvalue=False, text='IpInfo')
                self.IPInfo_button.place(x=240, y= 170)


    def quit(self):#
        # Quit the application when quit button is pressed
        exit()
    

    def domain_report(self):
        # If master toggle is pressed run this
        if self.Toggles['Domain']['Master'].get():
            domain_name = input('Enter Domain Name: ') # User input 
            if self.Toggles['Domain']['VirusTotal'].get():
                ratings, DNS_records = self.VirusTotal(domain_name) # Run VirusTotal Function with parameter domain_name
            if self.Toggles['Domain']['BufferOverrun'].get():
                certificates = self.BufferOverrun(domain_name)# IP[0] SHA_256[1] ORG[2] CN[3:-1]
            if self.Toggles['Domain']['SubBrute'].get():
                subdomains = os.system(f'{os.getcwd()}\windows\subbrute.exe {domain_name} -o subdomains.txt') # Run subbrute program, outputted to a text file in same directory with name 'subdomains.txt'
            
            with open(f'{domain_name}_Report.txt', 'w') as file:
                file.write(f'Domain Report for {domain_name}\n')
                if self.Toggles['Domain']['VirusTotal'].get():
                    file.write('\nWeb rating\n')
                    for rating in ratings:
                        file.write(f'{rating}: {ratings[rating]}\n')
                    file.write('\nPast DNS Records\n')
                    for record in DNS_records:
                        file.write(record['value']+'\n')
                if self.Toggles['Domain']['BufferOverrun'].get():
                    file.write('\nIPv4 Certificates\n')
                    if certificates != None: 
                        for IPv4_certificate in certificates:
                            certificate = IPv4_certificate.split(',') # Split parameters from string into list on the character `,`
                            file.write(f'Organisation: {certificate[2]}\nIP: {certificate[0]}\nSHA_256: {certificate[1]}\nCN: {certificate[3:-1][0]}\n\n')
                    else:
                        file.write('None\n')
                if self.Toggles['Domain']['SubBrute'].get():
                    file.write('\nSubdomains\n')
                    with open('subdomains.txt','r') as subdomains_file:
                        subdomains = subdomains_file.readlines()
                    for domain in subdomains:
                        file.write(domain+'\n')


    def IP_report(self):
        # If master toggled run this
        if self.Toggles['IP']['Master'].get():
            IP_address = input('Enter IP Address: ')
            if self.verify_IP(IP_address): # Runs IP_address through regex
                if self.Toggles['IP']['Ports'].get():
                    open_ports = self.Port_scanner(IP_address) # Sends IP to port scanner function with IP_Address as parameter
                if self.Toggles['IP']['IpInfo'].get():
                    location = self.IpInfo(IP_address)
                
                with open(f'{IP_address}_Report.txt', 'w') as file:
                        file.write(f'IP Report for {IP_address}\n')
                        if self.Toggles['IP']['Ports'].get():
                            file.write('\nOpen Ports\n')
                            for port in open_ports:
                                file.write(f'Open Port: {port}\n')
                        if self.Toggles['IP']['IpInfo'].get():
                            file.write('\nIP Location\n')
                            file.write(f'hostname: {location[0]}\n')
                            file.write(f'city: {location[1]}\n')
                            file.write(f'region: {location[2]}\n')
                            file.write(f'co-ordinates: {location[3]}\n')
            else:
                pass


    def verify_IP(self, IP):
        if re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", IP): # Checks that format follows x.x.x.x with x being 1 - 3 characters which is an integer 
            return True
        else:
            return False


    def Port_scanner(self, IP):
        lower_range = int(input('Enter lower port range: '))
        if lower_range > 65535: lower_range = 65535 # If integer is too high, set to max port number
        upper_range = int(input('Enter upper port range: '))
        if upper_range > 65535: upper_range = 65535 # If integer is too high, set to max port number
        if lower_range > upper_range:
            upper_range, lower_range = lower_range, upper_range # If inputted the wrong way round, change them to prevent errors
        open_ports = []
        for port in range(lower_range, upper_range+1):
            res = self.scan_port(IP, port) # Run scan_port with parameters IP and port
            if res != None:
                open_ports.append(port)
        return open_ports
        
            
    def scan_port(self, IP, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a socket
        sock.settimeout(1) # Make timeout low to speed up

        try:
            if self.debug: print(f'{port=}')
            result = sock.connect_ex((IP, port)) # Try to connect to the IP&Port connect_ex will return the error code 
            if result == 0: # If successful
                return port
        except:
            pass
        finally:
            # Close the socket
            sock.close()


    def VirusTotal(self, domain):
        if self.debug: print('Running VirusTotal')
        # Set headers as shown in documentation
        headers = {'accept': 'application/json',
                    'x-apikey': self.VirusTotal_API}
        # Send a request to the api domain
        response = requests.get(f'{self.VirusTotal_URL}{domain}', headers = headers)
        if response.status_code == 200: # If response 
            text = response.text 
            json_file = json.loads(text) # Load JSON element from the response
            ratings = json_file['data']['attributes']['last_analysis_stats']
            DNS_records = json_file['data']['attributes']['last_dns_records']

            return ratings, DNS_records
        else:
            raise ApiKeyError('VirusTotal')
    

    def BufferOverrun(self, domain):
        if self.debug: print('Running Buffer')
        # Set headers as shown in documentation
        headers = {'x-api-key': self.BufferOverrun_API}
        # Send response to API domain
        response = requests.get(f'{self.BufferOverrun_URL}{domain}', headers = headers)
        if response.status_code == 200: # If response
            text = response.text
            json_file = json.loads(text) # Load JSON
            IPv4_certificates = json_file['Results']

            return IPv4_certificates
        else:
            raise ApiKeyError('BufferOverrun')
    

    def IpInfo(self, address):
        if self.debug: print('Running IpInfo')
        response = requests.get(f'https://ipinfo.io/{address}/geo')
        if response.status_code == 200: # If response 
            text = response.text
            json_file = json.loads(text) # Load JSON
            try:
                hostname, city, region, location = json_file['hostname'], json_file['city'], json_file['region'], json_file['loc'] # Try to parse all the variables
            except KeyError: # Sometimes returns ()
                return (None, None, None, None)
            return (hostname, city, region, location)
        else:
            raise ApiKeyError('IpInfo')
    

    def decrypt(self, input):
        string = bytes(input, 'utf-8')
        # Decode Base64 for my API tokens
        return_value = b64decode(string).decode()
        return return_value

Program = osint()
# Run the application
Program.mainloop()