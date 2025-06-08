### Cybersecurity Learning Projects ##

## What This Repo Is
This is for educational purpose, not a professional toolkit. The goal is to:
- Reinforce theoretical knowledge with real code.
- Improve Python skills through practical challenges related to cyber security.
- Build a strong foundation for ethical hacking and bug hunting.

## Note:
Some packages are non-Debian-packaged Python package like scapy etc cannot be installed globally because debian don’t trust that So they requires virtual environment to be run. So it is better to run all scripts inside virtual env using below command:

sudo apt install python3.11 python3.11-venv 
python3.11 -m venv venv
source venv/bin/activate # activate virtual environment
pip install -r requirements.txt so on..

## ********** Project Overview **********

### PortScanner
This script is a Python-based multi-threaded port scanner designed to quickly scan a range of TCP ports on a given host. It resolves the target, connects using sockets, and attempts to grab service banners (like HTTP Server headers).

**Usage:**
python3 fast_port_scanner.py <HOST> <START_PORT> <END_PORT> <THREADS>

### Sniffer
 This script is a simple packet sniffer written in Python using Scapy and Colorama for colored output. It captures HTTP requests, src IP and dst IP addresses, and TCP port info from a given network interface same like as wireshark.
 
**Usage:**
python3 packet-sniffer.py <Network-interface like eth0>

### Multi-Threaded Hash Cracker (MD5, SHA1, SHA256)
This is a simple brute-force hash cracker implemented in Python that uses multiple threads to crack hashed passwords using a dictionary (password.txt).
It supports MD5, SHA1, and SHA256 hashes.
Works on python3.6 or higher

**Usage:**(require password.txt file)
python3 hash_cracker.py <hashed_string> <hash_type> <threads>
like python3 hash_cracker.py  294de3557d9d00b3d2d8a1e6aab028cf md5 100

### HTML Form Password Guesser (Multi-threaded)
This tool is a fast and simple brute-force password guesser for HTML forms (login pages), using requests, argparse, and Python's threading and queue. It sends repeated login attempts by dynamically modifying a specified field with candidate passwords.

Features:
Multi-threaded for faster performance
Detects successful login by matching a success message in the response
Reads passwords from password.txt
Spoofs User-Agent to mimic real browser
works for Content-Type: application/json

**Usage:**
python3 form_guesser.py -u <url> -d {} -m POST -s <success_message> -t <threads>      like
python3 form_guesser.py -u https://miro.com/api/v1/auth?s= -d '{"email":"<Your_email>","password":"FUZZ"}' -m POST -s "token" -t 1

### Info gathering
A basic OSINT (Open Source Intelligence) info-gathering tool designed to collect and print key domain and IP-related information using multiple libraries like whois, dnspython, shodan, requests, and some standard modules.
NOTE: Replace shodan apikey with yours

**Usage:**
python3 info_gathering.py -d google.com -o outfile.txt
python3 info_gathering.py -h

### ARP_SPOOFER(works only on windows)
A basic ARP spoofing (poisoning) tool written in Python using Scapy. It performs Man-in-the-Middle (MitM) attacks on a local network by tricking two devices (usually a victim and the router) into sending their traffic through the attacker’s machine — making the attacker act as a fake bridge between them.

**Usage:**
python3 arp_spoofer.py

## Network Scanner
This is a network scanner that uses ARP requests to find devices in the local network and then ICMP ping to double-check which IPs are alive.

**Usage:**(specially used in window)
python3 network_scanner.py 192.168.1.0/24  
NOTE: It usually scan ip range from  192.168.1.0 to 192.168.1.254, altogether 254 ips..

## ssh_and_ftp_bruteforcer
This Python script is a multi-threaded brute-force tool for attempting login on SSH or FTP services using a list of passwords. It leverages paramiko for SSH and ftplib for FTP.

**Usage:**
python3 ssh_ftp_guesser.py <host> <thread> <ssh or ftp>
It requires password.txt file with the list of password for bruteforce.

## A malware(Keylogger)
This is a multifunctional Python-based malware that logs keystrokes, provides a reverse shell for remote command execution, and achieves persistence via Windows Registry. It's designed to operate stealthily and maintain long-term access to the target system

## WebApp Penesting
1) Directory_Buster
multithreaded Python-based directory brute-forcing tool, similar to DirBuster, used to discover hidden files and directories on a web server using a wordlist. It supports optional file extensions and handles connection errors gracefully during enumeration.

**Usage:**
requires wordlists/directory.txt file with list of dir name
python3 directory_buster.py https://<domain> <threads> <extension_file(optional)>

2) Recursive_Web_Crawler
A multithreaded web crawler that recursively discovers internal links on a domain using BeautifulSoup. It saves all discovered URLs into a domain-named text file for further reconnaissance or spidering.

**Usage:**
python3 recursive_web_crawler.py https://www.google.com <threads>

3) Subdomain Finder
A fast, multithreaded subdomain brute-forcer that enumerates active subdomains of a target domain using a wordlist. It highlights live subdomains in green for better visibility using colorama.

**Usage:**
python3 subdomain_finder.py google.com <threads>
Requires wordlists/subdomain.txt file

4) Web_vulnerability_Scanner
This Python script is a basic vulnerability scanner designed to detect SQL Injection and Cross-Site Scripting (XSS) flaws in web applications by crawling forms on given URLs and injecting common payloads.

**Usage:**
python3 web_vulnerability.py (http://testphp.vulnweb.com/login.php)
Works on Content-type=application/x-www-form-urlencoded

## Automate_Recon
For automate_recon Fork it from https://github.com/CalfCrusher/RobinHood and apply any environment-specific changes.
