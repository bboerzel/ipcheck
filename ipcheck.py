
#!/usr/bin/env python

"""
IP Security Check
 This script is a quick and dirty solution to check an IPv4 address.
 You need an API Key for VirusTotal and OTX, which you can get for free.
 The free tiers are more than enough for a couple of manual IP checks a day.
 You may need to: pip install requests dnspython colorama vt-py OTXv2 iptools

https://github.com/bboerzel/ipcheck

Author: Benjamin Börzel 
Twitter: @boerzel

version: 0.1
last change: 2022.03.30

Changelog
v0.1
 Initial Script

"""


from msilib.schema import Error
import requests, sys, getopt, json, argparse, get_malicious, hashlib, vt, dns.resolver, dns.reversename, iptools
from OTXv2 import OTXv2
from colorama import Fore, Back, Style

API_KEY_VT = 'ENTERKEY'
API_KEY_OTX = 'ENTERKEY'

# check if we got an argument, if not exit
try:
    ip = sys.argv[1]
except IndexError:
    raise SystemExit(f"Usage: {sys.argv[0]} IPv4")

# check if argument is an ipv4, if not exit
ip_check = iptools.ipv4.validate_ip(ip)
if ip_check is False:
    raise SystemExit(f"No valide IP address. Usage: {sys.argv[0]} 127.0.0.1")

# get the DNS name
print(Back.LIGHTBLACK_EX+"Hostname"+Style.RESET_ALL)
try:
    addrs = dns.reversename.from_address(ip)
    hostname= str(dns.resolver.resolve(addrs,"PTR")[0])
    print("Hostname: "+hostname)
except:
    print("hostname error")

# get infos from https://ip-api.com
print(Back.LIGHTBLACK_EX+"\nIP Infos"+Style.RESET_ALL)
ipapi = requests.get(f'http://ip-api.com/json/{ip}').json()
print("Country: "+ipapi["country"]+", "+ipapi["city"])
print("Organisation: "+ipapi["org"])
print("ISP: "+ipapi["isp"])
print("ASN: "+ipapi["as"])

# get infos from https://otx.alienvault.com
print(Back.LIGHTBLACK_EX+"\nOTX"+Style.RESET_ALL)
otx = OTXv2(API_KEY_OTX, server="https://otx.alienvault.com/")
alerts = get_malicious.ip(otx, ip)
if len(alerts) > 0:
    print(Fore.RED+'Identified as potentially malicious'+Style.RESET_ALL)
    print(str(alerts))
else:
    print(Fore.GREEN+'Unknown or not identified as malicious'+Style.RESET_ALL)

# get infos from https://virustotal.com
print(Back.LIGHTBLACK_EX+"\nVirustotal"+Style.RESET_ALL)
url_vt = "https://www.virustotal.com/api/v3/ip_addresses/"+ip
headers_vt = {"Accept": "application/json","x-apikey": API_KEY_VT}
json_vt = requests.request("GET", url_vt, headers=headers_vt).json()
print(Fore.GREEN+"harmless: "+str(json_vt["data"]["attributes"]["last_analysis_stats"]["harmless"])+Style.RESET_ALL)
print(Fore.YELLOW+"suspicious: "+str(json_vt["data"]["attributes"]["last_analysis_stats"]["suspicious"])+Style.RESET_ALL)
print(Fore.RED+"malicious: "+str(json_vt["data"]["attributes"]["last_analysis_stats"]["malicious"])+Style.RESET_ALL)
print("undetected: "+str(json_vt["data"]["attributes"]["last_analysis_stats"]["undetected"]))

# get infos from blocklist.de
print(Back.LIGHTBLACK_EX+"\nblocklist.de"+Style.RESET_ALL)
response = requests.get(f'http://api.blocklist.de/api.php?ip={ip}') 
print(response.text.replace("<br />","\n"))
