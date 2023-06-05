import socket
import sys

print("SIMPLE PORT SCANNER")
usage = "Python3 port_scanner.py HOST START_PORT END_PORT"

if len(sys.argv) < 4 or len(sys.argv) > 4:
    print(usage)
    sys.exit()

host = sys.argv[1]
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])
timeout = 1.0  # set timeout to 1 second

try:
    if host and start_port and end_port:
        for port in range(start_port, end_port+1):
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.settimeout(timeout)  # set the timeout for the socket
            conn = soc.connect_ex((host, port))
            if not conn:
                 print(f"port {port} is open")
            soc.close()  # close the socket after use

except socket.error as e:
    print(e)
    sys.exit()
