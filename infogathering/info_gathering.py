import whois
import dns.resolver
import shodan
import requests
import sys
import json
import argparse
import socket

parser = argparse.ArgumentParser(description="This is basic info_gathering tool.", usage="Python3 info_gathering.py -d DOMAIN  [-s IP]")
parser.add_argument("-d", "--domain", help="Enter the domain name for foot printing", required=True)
parser.add_argument("-s", "--shodan", help="Enter Ip for shodan search")
parser.add_argument("-o", "--output", help="output file")

args = parser.parse_args()
domain = args.domain
ip = args.shodan
output = args.output

  
#Whois module
print1 = ''
print1 += "--------------------------------\n"
print1 += "[+] Setting whois info...\n"
print1 += "--------------------------------\n"
print(print1)

whoisresult = ''
try:
    #Using whois library, creating instance
    detail = whois.whois(domain)
    whoisresult += f"[+] whois info found: \n"
    whoisresult += f"[+] Domain Name: {detail.name}\n"
    whoisresult += f"[+] Registry Domain ID: {detail.tld}\n"
    whoisresult += f"[+] Registrant_country: {detail.registrant_country}\n"
    whoisresult += f"[+] Registrar: {detail.registrar}\n"
    whoisresult += f"[+] Owner: {detail.owner}\n"
    whoisresult += f"[+] Name_servers: {detail.name_servers}\n"
    whoisresult += f"[+] Abuse_contact: {detail.abuse_contact}\n"
    whoisresult += f"[+] Emails: {detail.emails}\n"
    whoisresult += f"[+] Tld: {detail.tld}\n"
    whoisresult += f"[+] Creation_date: {detail.creation_date}\n"
    whoisresult += f"[+] Expiration_date: {detail.expiration_date}\n"
    whoisresult += f"[+] Last_updated: {detail.last_updated}\n"
    print(whoisresult)
except Exception as e:
    print(e)

#dns Module
print2 = ''
print2 += "--------------------------------\n"
print2 += "[+] Getting DNS info...\n"
print2 += "--------------------------------\n"
print(print2)

#Implementating dns.resolver from dnspython
dnsresolver = ''
try:
    for dnsA in dns.resolver.resolve(domain, "A"):
        dnsresolver += f"[+] A record is: {dnsA}\n"
    dnsresolver += "==> Name Servers: \n"
    for dnsNS in dns.resolver.resolve(domain, "NS"):
        dnsresolver += f"[+] NS record is: {dnsNS}\n"
    dnsresolver += "==> Mail Server: \n"
    for dnsMX in dns.resolver.resolve(domain, "MX"):
        dnsresolver += f"[+] MX record is: {dnsMX}\n"
    dnsresolver += "==> Text Record: \n"
    for dnsTXT in dns.resolver.resolve(domain, "txt"):
        dnsresolver += f"[+] Txt record is: {dnsTXT}\n"
    print(dnsresolver)
  
except Exception as e:
    print(e)

#etting geolocation Info
print3 = ''
print3 += "\n"
print3 += "--------------------------------\n"
print3 += "[+] Setting Geolocation info...\n"
print3 += "--------------------------------\n"
print(print3)
try:
    geolocation =''
    url = "https://geolocation-db.com/json/"
    response = requests.get(url + socket.gethostbyname(domain)).json()
    geolocation += f"[+] The Country is: {response['country_name']}\n"
    geolocation += f"[+] The Country_code is: {response['country_code']}\n"
    geolocation += f"[+] The City is: {response['city']}\n"
    geolocation += f"[+] The Latitude is: {response['latitude']}\n"
    geolocation += f"[+] The Longitude is: {response['longitude']}\n"
    geolocation += f"[+] The Ipv4 is: {response['IPv4']}\n"
    print(geolocation)

    # res = response.content
    # jsons = json.loads(res)
    # print(jsons["country_code"])
except Exception as e:
    print(e)

#Shodan Info
if (shodan):
    print4 = ''
    print4 += "\n"
    print4 += "--------------------------------\n"
    print4 += "[+] Getting Shodan info...\n"
    print4 += "--------------------------------\n"
    print(print4)
    try:
        shodan1 = ''
        api = shodan.Shodan('GfY03h8CwqaXi7rx5RG6NI4DZjUGJZqx')

        # Lookup an IP
        results = api.search(ip)
        shodan1 += f"[+] Results found: {results['total']}\n"
        for result in results['matches']:
            shodan1 += f"IP: {result['ip_str']}\n"
            shodan1 += f"Data: \n{result['data']}\n"
            shodan1 += ""
        print(shodan1)

    except Exception as e:
        print(e)



if (output):
    with open(output, "w") as o:
        a = print1+whoisresult+print2+dnsresolver+print3+geolocation+print4+shodan1
        o.write(a)
