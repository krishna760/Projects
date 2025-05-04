#Scapy is a packet manipulation tool for computer networks, originally written in Python by Philippe Biondi. 
#It can forge or decode packets, send them on the wire, capture them, and match requests and replies. 
#It can also handle tasks like scanning, tracerouting, probing, unit tests, attacks, and network discovery.

#IN TERMINAL
# #>sudo scapy
# #packet = IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=80)
# #packet.show()
# #packet[TCP].show()
# #packet[HTTPRequest].show()
# #send(packet)
# #ls(IP)
# #sniff(iface='eth0')
# #capture = sniff(iface='eth0')
# #capture.summary()
# #packets = sniff(count=10)
# #print(packets)

# from  scapy.all import *
# from scapy.layers.inet import IP
# from scapy.layers.http import HTTPRequest, TCP
# from colorama import init, Fore

# init()

# red = Fore.RED
# green =Fore.GREEN
# blue = Fore.BLUE
# yellow = Fore.YELLOW
# reset = Fore.RESET

#Capturing TCP Packet
# def sniff_packets(iface):
#     if iface:
        # sniff(prn = process_packet, iface = iface, store=False)
    # else:
    #     sniff(prn = process_packet, store=False)

# def process_packet(packet):
#     if packet.haslayer(TCP):
#         src_ip = packet[IP].src
#         dst_ip = packet[IP].dst
#         src_port = packet[TCP].sport
#         dst_port = packet[TCP].dport

        # print(f"{red}[+] {src_ip} is using port {src_port} to connect to {dst_ip} at port {dst_port}{reset}")

# Capturing http packet
    # if packet.haslayer(HTTPRequest):
    #     url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
    #     print(url)
    #     method = packet[HTTPRequest].Method.decode()
    #     print(f"{green} [+] {src_ip} is making a HTTP request to {url} url method {method}{reset}")
    #     print(f"{yellow} {packet[HTTPRequest].show()}")
    #     if packet.haslayer(Raw):
    #         print(f"{blue}[+] Useful raw data: {packet.getlayer(Raw).load.decode()}{reset}")

# iface = sys.argv[1]
# sniff_packets(iface)



from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest,TCP
import sys
from colorama import Fore

green = Fore.GREEN
red = Fore.RED
yellow = Fore.YELLOW
blue = Fore.BLUE
reset = Fore.RESET

def capture(interface):
    if interface:
        sniff(prn=packet_capture, iface=interface, store=False)
    else:
        sniff(prn=packet_capture, store=False)

def packet_capture(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Check if the packet is an HTTP request
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            method = http_layer.Method.decode()
            host = http_layer.Host.decode()
            path = http_layer.Path.decode()

            print(f"{green}[HTTP Request]{reset} {method} {host}{path}")

        # Print IP and TCP information
        print(f"{blue}[IP]{reset} {ip_layer.src} -> {ip_layer.dst}")
        print(f"{yellow}[TCP]{reset} {tcp_layer.sport} -> {tcp_layer.dport}")

arg = sys.argv[1] 
capture(arg)
