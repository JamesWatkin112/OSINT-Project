import requests
import os
import json

# API KEYS with URL
VirusTotal_API, VirusTotal_URL = '5c558621fc6c855ff36fe585a2e62526b5adcefe4e5b424f82eb204bdea8b7b9', 'https://www.virustotal.com/api/v3/domains/'
BufferOverrun_API, BufferOverrun_URL = 'M5sa542kcyaBTKSLpY9xO186NG6U5HPJ3Pjwd0P8', 'https://tls.bufferover.run/dns?q='

# ----------------------------------------------------------------------------------------------------------------------------------------------------------

Toggles = {'Domain':
            {'Master': False,
             'VirusTotal': True,
             'SubBrute': False,
             'BufferOverrun': True},
           'Email':
            {'Master': True,
             'Debounce':False}
          }

domain = None
report_file = 'report.txt'

class ApiKeyError(Exception):
    def __init__(self, program):
        self.message = f'Api Key Error for program: {program}'
        super().__init__(self.message)


def VirusTotal(domain):
    headers = {'accept': 'application/json',
                'x-apikey': VirusTotal_API}
    response = requests.get(f'{VirusTotal_URL}{domain}', headers = headers)
    if response.status_code == 200:
        text = response.text
        json_file = json.loads(text)
        ratings = json_file['data']['attributes']['last_analysis_stats']
        DNS_records = json_file['data']['attributes']['last_dns_records']

        return ratings, DNS_records
    else:
        raise ApiKeyError('VirusTotal')


def BufferOverrun(domain):
    headers = {'x-api-key': BufferOverrun_API}
    response = requests.get(f'{BufferOverrun_URL}{domain}', headers = headers)
    if response.status_code == 200:
        text = response.text
        json_file = json.loads(text)
        IPv4_certificates = json_file['Results']

        return IPv4_certificates
    else:
        raise ApiKeyError('BufferOverrun')

def Domain_Report(domain):
    if Toggles['Domain']['Master']:
        if Toggles['Domain']['VirusTotal']:
            ratings, DNS_records = VirusTotal(domain)

        if Toggles['Domain']['BufferOverrun']:
            IPv4_certificates = BufferOverrun(domain) # IP[0] SHA_256[1] ORG[2] CN[3:-1]

        if Toggles['Domain']['SubBrute']:
            os.system(f'{os.getcwd()}\windows\subbrute.exe {domain} -o subdomains.txt')
        
        # File writing
        with open(report_file, 'w') as file:
            file.write(f'Domain Report for {domain}\n')
            file.write('\nWeb rating\n')
            for rating in ratings:
                file.write(f'{rating}: {ratings[rating]}\n')
            file.write('\nPast DNS Records\n')
            for record in DNS_records:
                file.write(record['value']+'\n')
            file.write('\nIPv4 Certificates\n')
            if IPv4_certificates != None:
                for IPv4_certificate in IPv4_certificates:
                    certificate = IPv4_certificate.split(',')
                    file.write(f'Organisation: {certificate[2]}\nIP: {certificate[0]}\nSHA_256: {certificate[1]}\nCN: {certificate[3:-1][0]}\n\n')
            else:
                file.write('None\n')
            file.write('\nSubdomains\n')
            with open('subdomains.txt','r') as subdomains_file:
                subdomains = subdomains_file.readlines()
            for domain in subdomains:
                file.write(domain+'\n')

def Email_Report(address):
    if Toggles['Email']['Master']:
        pass
            
if domain == None:
    domain = input('Enter a domain name: ')
Domain_Report(domain)