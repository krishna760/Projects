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
            response = requests.get(urls, allow_redirects=True)
            if response.status_code == 200:
                print(f"[+] Directory found: {str(response.url)}")
        except (requests.exceptions.RequestException, ConnectionResetError) as e:
            print(f"[!] Connection error occurred: {e}")
            # Retry the request after a delay
            sleep(1)
            try:
                response = requests.get(urls, allow_redirects=True)
                if response.status_code == 200:
                    print(f"[+] Directory found: {urls}")
            except (requests.exceptions.RequestException, ConnectionResetError) as e:
                print(f"[!] Failed to retrieve directory: {urls}. Error: {e}")
        q.task_done()



q = queue.Queue()
wordlist = open("wordlists/directory_list.txt", "r")

for i in wordlist.read().splitlines():
    if ext:
        url = host + "/" + i + ext
        q.put(url)
    else:
        url = host + "/" + i
        q.put(url)

for thread in range(threads):
    t = threading.Thread(target = dirbuster, args=(thread,), daemon=True)
    t.start()

q.join()
