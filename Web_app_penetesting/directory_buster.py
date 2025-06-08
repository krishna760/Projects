import requests, queue, threading, sys
from time import sleep

host = sys.argv[1]
threads = int(sys.argv[2])
try:
    ext = sys.argv[3]
except:
    ext = False
    pass

try:
    response = requests.get(host)
except Exception as e:
    print(e)
    exit(0)

def dirbuster(thread):
    while not q.empty():
        urls = q.get()
        try:
            response = requests.get(urls, allow_redirects=False)
            if response.status_code == 200:
                print(f"[+] Directory found: {str(response.url)}")
        except Exception as e:
                print(f"[!] Error occurred: {e}")

        q.task_done()



q = queue.Queue()
wordlist = open("wordlists/directory.txt", "r")

extensions = []
# Load extensions from the file if ext is provided
if ext:
    try:
        with open(ext, "r") as f:
            extensions = f.read().splitlines()
    except FileNotFoundError:
        print(f"[!] Extension file '{ext}' not found.")
        exit(1)

# Queue construction
for i in wordlist.read().splitlines():
    if extensions:
        for e in extensions:
            url = host + "/" + i + e
            q.put(url)
    else:
        url = host + "/" + i
        q.put(url)

for thread in range(threads):
    t = threading.Thread(target = dirbuster, args=(thread,), daemon=True)
    t.start()

q.join()
