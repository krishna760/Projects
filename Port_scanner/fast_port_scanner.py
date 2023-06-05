import socket
import sys
import queue
import threading
import time
import requests

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
timeout = 1.0  # set timeout to 1 second
result="Result: \nPORT\tSTATE\tSERVICE\n"

try:
    target = socket.gethostbyname(host)
    print(target)
except:
    print("[+] Host resolution failed")
    exit()

def get_banner(port, soc):
    if port == 80:
        response = requests.get("http://"+ target)
        return response.headers['Server']
    try:
        return soc.recv(1024).decode()
    except:
        return "Not Found"

def scan_port(t_no):
    global result
    while not q.empty():
        port = q.get()
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.settimeout(timeout)  # set the timeout for the socket
            conn = soc.connect_ex((host, port))
            if not conn:
                banner = get_banner(port, soc)
                banner = ''.join(banner.splitlines())
                result += f"{port}\tOPEN\t{banner}\n"
            soc.close()  # close the socket after use
        except:
            pass
        q.task_done()

q= queue.Queue()
for j in range(start_port, end_port+1):
    q.put(j)
for i in range(thread_no):
    t = threading.Thread(target=scan_port, args=(i, ))
    t.start()
        
q.join()
print(result)







# import socket
# import sys
# import threading

# print("SIMPLE PORT SCANNER")
# usage = "Python3 port_scanner.py HOST START_PORT END_PORT THREADS"

# if len(sys.argv) < 5 or len(sys.argv) > 5:
#     print("usage: ", usage)
#     sys.exit()

# host = sys.argv[1]
# start_port = int(sys.argv[2])
# end_port = int(sys.argv[3])
# threads = int(sys.argv[4])
# timeout = 1.0  # set timeout to 1 second

# def scan_port(port):
#     # print(f"scanning port {port}")
#     soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     soc.settimeout(timeout)  # set the timeout for the socket
#     conn = soc.connect_ex((host, port))
#     if not conn:
#         print(f"port {port} is open: ")
#     soc.close()  # close the socket after use

# try:
#     if host and start_port and end_port and threads:
#         threads_list = []
#         for port in range(start_port, end_port+1):
#             t = threading.Thread(target=scan_port, args=(port,))
#             threads_list.append(t)
#             # print(threads_list)
#             if len(threads_list) == threads:
#                 for t in threads_list:
#                     t.start()
#                 for t in threads_list:
#                     t.join()
#                 threads_list = []

#         if threads_list:
#             for t in threads_list:
#                 t.start()
#             for t in threads_list:
#                 t.join()

# except socket.error as e:
#     print(e)
#     sys.exit()



# import socket
# import sys
# import ipaddress
# import threading

# print("SIMPLE PORT SCANNER")
# usage = "python3 fast_port_scanner.py HOST START_PORT END_PORT"

# if len(sys.argv) < 4 or len(sys.argv) > 4:
#     print("usage: ", usage)
#     sys.exit()

# host = sys.argv[1]
# start_port = int(sys.argv[2])
# end_port = int(sys.argv[3])
# # threads = int(sys.argv[4])
# results = "Result: \nPORT\tSTATE\n"

# def port_scan(port):
#     try:
#         global results
#         # print(f"Scanning port {port}")
#         soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         soc.settimeout(3)
#         # resolve_host = ipaddress.ip_address(socket.gethostbyname(host))
#         # print(resolve_host)
#         conn = soc.connect_ex((host, port))
#         if not conn:
#             results += f"{port}\tOPEN\n"
#         soc.close()
#     except:
#         pass
        
# try:
#     if host and start_port and end_port:
#         thread_list = []
#         for port in range(start_port, end_port+1):
#             thread0 = threading.Thread(target=port_scan, args=(port, ))
#             thread_list.append(thread0)
#             thread0.start()
#         for i in thread_list:
#             i.join()
# except threading.ThreadError as e:
#     print(e)

# print(results)
# print("Finished")
