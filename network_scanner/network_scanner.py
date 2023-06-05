# from scapy.all import srp, sr1
# from scapy.layers.l2 import ARP, Ether
# from scapy.layers.inet import IP, ICMP
# import sys
# import ipaddress

# target_network = sys.argv[1]

# ether = Ether(dst = 'ff:ff:ff:ff:ff:ff')
# arp = ARP(pdst= target_network)
# probe = ether/arp
# print(probe)

# result = srp(probe, timeout = 10, verbose=0)
# print(result)
# online_clients = []
# answered = result[0]
# print(answered)
# for sent, received in answered:
#     online_clients.append({'ip' : received.psrc, 'mac' : received.hwsrc})

# print()
# print("[+] Available hosts:")
# print("IP"+" " *30 + "MAC")
# for client in online_clients:
#     print('[+] {}\t\t{}'.format(client['ip'], client['mac']))


# print("------------------------")
# print("[+] Scanning with ICMP..")
# print("------------------------")
# ip_list = [str(ip) for ip in ipaddress.IPv4Network(target_network, False)]

# for ip in ip_list:
#     probe = IP(dst = ip)/ICMP()
#     result = sr1(probe, timeout=3)
#     if result:
#         print("[+] {} is online".format(ip))




from scapy.all import srp, sr1
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether
import sys
import ipaddress

target_network = sys.argv[1]

ether = Ether(dst='ff:ff:ff:ff:ff:ff')
arp = ARP(pdst=target_network)
probe = ether/arp

results = srp(probe, timeout = 10, verbose=0)
answer = results[0]
online_clients = []
for sends, receives in answer:
    online_clients.append({'ip' : receives.psrc, 'mac' : receives.hwsrc})

print()
print("[+] Available hosts:")
print("IP"+" "*30 + "MAC")

for client in online_clients:
    print('[+] {}\t\t{}'.format(client['ip'], client['mac']))
    

#for icmp packet
lst = [str(ip) for ip in ipaddress.IPv4Network(target_network, False)]

for ip in lst:
    probe = IP(dst = ip)/ICMP()
    result = sr1(probe, timeout=3)
    if result:
        print("[+] {} is online".format(ip))
