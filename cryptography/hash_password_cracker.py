from hashlib import md5, sha256, sha1
import sys, threading, queue
import time

uncracked = True
correct_password = ''
start_time = time.perf_counter()
q = queue.Queue()

def md5_crack():
    global uncracked, correct_password
    while uncracked and not q.empty():
        pwd = q.get()
        print(f"[+] Trying.. {pwd}")
        if md5(pwd.encode("utf-8")).hexdigest() == sample_hashed:
            print(f"[+] Md5 Hash matched for: {pwd}")
            uncracked = False
            correct_password = pwd
        q.task_done()


def sha1_crack():
    global uncracked, correct_password
    while uncracked and not q.empty():
        pwd = q.get()
        print(f"[+] Trying.. {pwd}")
        if sha1(pwd.encode("utf-8")).hexdigest() == sample_hashed:
            print(f"[+] Sha1 Hash matched for: {pwd}")
            uncracked = False
            correct_password = pwd
        q.task_done()


def sha256_crack():
    global uncracked, correct_password
    while uncracked and not q.empty():
        pwd = q.get()
        print(f"[+] Trying.. {pwd}")
        if sha256(pwd.encode("utf-8")).hexdigest() == sample_hashed:
            print(f"[+] Sha256 Hash matched for: {pwd}")
            uncracked = False
            correct_password = pwd
        q.task_done()

sample_hashed = sys.argv[1]
type = sys.argv[2]
threads = int(sys.argv[3])
threads_list = []

with open("password.txt", "r") as file:
    for password in file.read().splitlines():
        q.put(password)
 
if type == 'md5':
    for i in range(threads):
        t = threading.Thread(target=md5_crack, daemon=True)
        t.start()
        threads_list.append(t)

elif type == 'sha1':
    for i in range(threads):
        t = threading.Thread(target=sha1_crack, daemon=True)
        t.start()
        threads_list.append(t)

elif type == 'sha256':
    for i in range(threads):
        t = threading.Thread(target=sha256_crack, daemon=True)
        t.start()
        threads_list.append(t)
else:
    pass

for t in threads_list:
    t.join()

if uncracked == False:
    print(f"[+] Given hash  cracked with password: {correct_password}")
    end_time = time.perf_counter()
    print(f"Time taken: {end_time-start_time}")

