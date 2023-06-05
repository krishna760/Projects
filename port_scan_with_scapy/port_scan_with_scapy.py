from scapy.all import *
from scapy.layers.inet import IP, TCP
import socket
import sys
import queue
import threading
import time

time1 = time.perf_counter()

print("SIMPLE PORT SCANNER")
usage = "Python3 port_scanner.py HOST START_PORT END_PORT THREADS"

if len(sys.argv) < 5 or len(sys.argv) > 5:
    print(usage)
    sys.exit()

host = sys.argv[1]
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])
thread_no = int(sys.argv[4])
timeout = 2  # set timeout to 1 second
result="Result: \nPORT\tSTATE\n"

try:
    target = socket.gethostbyname(host)
    # print(target)
except:
    print("[+] Host resolution failed")
    exit()


def scan_port(t_no):
    global result
    while not q.empty():
        port = q.get()
        print(f"Scanning for port {port}")
        conf.verb = 0
        try:
            synprobe = sr1(IP(dst = target)/TCP(sport = RandShort(), dport = port, flags = "S"), timeout=timeout)
            if synprobe:
                respflags = synprobe.getlayer(TCP).flags
                if respflags == 0x12:
                    result += f"{port}\tOPEN\n"
                else:
                    print(f"Unexpected response flags: {respflags}")
            else:
                print("No response received")
               
        except socket.gaierror as e:
            pass
        rstprobe = IP(dst = target)/TCP(sport = RandShort(), dport = port, flags = "R")
        send(rstprobe)
        q.task_done()

q= queue.Queue()
for j in range(start_port, end_port+1):
    q.put(j)
for i in range(thread_no):
    t = threading.Thread(target=scan_port, args=(i, ))
    t.start()
        
q.join()
print(result)