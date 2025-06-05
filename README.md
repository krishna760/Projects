### Cybersecurity Learning Projects ##

## What This Repo Is
This is a **learning lab**, not a professional toolkit. The goal is to:
- Reinforce theoretical knowledge with real code.
- Improve Python skills through practical challenges related to cyber security.
- Build a strong foundation for ethical hacking and bug hunting.

###### Project overview
 #PortScanner
This script is a Python-based multi-threaded port scanner designed to quickly scan a range of TCP ports on a given host. It resolves the target, connects using sockets,
and attempts to grab service banners (like HTTP Server headers).
Works on python3.6 or higher
Usage:
python3 fast_port_scanner.py <HOST> <START_PORT> <END_PORT> <THREADS>

 #Sniffing
 This script is a simple packet sniffer written in Python using Scapy and Colorama for colored output. It captures HTTP requests, src IP and dst IP addresses,
 and TCP port info from a given network interface same like as wireshark.
Usage:
python3 packet-sniffer.py <Network-interface like eth0>
If not works install packages in virtual env like
python3 -m venv env
source env/bin/activate (activate venv)
pip install scapy
pip install colorama          then run
python3 packet-sniffer.py <Network-interface like eth0>

 #hash_Password_Cracker
Multi-Threaded Hash Cracker (MD5, SHA1, SHA256)
This is a simple brute-force hash cracker implemented in Python that uses multiple threads to crack hashed passwords using a dictionary (password.txt).
It supports MD5, SHA1, and SHA256 hashes.
Works on python3.6 or higher
Usage:(require password.txt file)
python3 hash_cracker.py <hashed_string> <hash_type> <threads>
like python3 hash_cracker.py  294de3557d9d00b3d2d8a1e6aab028cf md5 100

## HTML Form Password Guesser (Multi-threaded)
This tool is a fast and simple brute-force password guesser for HTML forms (login pages), using requests, argparse, and Python's threading and queue.
It sends repeated login attempts by dynamically modifying a specified field with candidate passwords.
#Features:
Multi-threaded for faster performance
Detects successful login by matching a success message in the response
Reads passwords from password.txt
Spoofs User-Agent to mimic real browser
work for Content-Type: application/json
Usage:
python3 form_guesser.py -u <url> -d {} -m POST -s <success_message> -t <threads>      like
python3 form_guesser.py -u https://miro.com/api/v1/auth?s= -d '{"email":"kb5871353@gmail.com","password":"FUZZ"}' -m POST -s "token" -t 1

## Info gathering
A basic OSINT (Open Source Intelligence) info-gathering tool designed to collect and print key domain and IP-related information using multiple libraries:
whois, dnspython, shodan, requests, and some standard modules.
NOTE: Replace shodan apikey with yours
Usage:
python3 info_gathering.py -d google.com -o outfile.txt
python3 info_gathering.py -h

## ARP_SPOOFER
A basic ARP spoofing (poisoning) tool written in Python using Scapy. It performs Man-in-the-Middle (MitM) attacks on a local network by tricking two devices into thinking the attacker's machine is the other device.



