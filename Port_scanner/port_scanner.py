import socket
import sys

print("A simple port scanner")
usage="python3 scanner.py <host> <start_port> <end_port>"

if len(sys.argv) != 4:
    print (usage)
    sys.exit(1)

host=sys.argv[1]
start_port=int(sys.argv[2])
end_port=int(sys.argv[3])
print(f"Scanning {host} from port {start_port} to {end_port}")

try:
    for port in range(start_port, end_port+1):
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result=s.connect_ex((host, port))
        if result==0:
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")
        s.close()
except socket.error:
    print(f"Could not connect to {host}")
    sys.exit(1)
