import requests, sys, threading, queue
from colorama import init, Fore

init()

green = Fore.GREEN
reset = Fore.RESET

host = sys.argv[1]
threads = int(sys.argv[2])

def brute(thread):
    while not q.empty():
        subdomain = q.get()
        url = f"https://{subdomain}.{host}"
        try:
            response = requests.get(url, allow_redirects=False, timeout=2)
            if response.status_code == 200:
                print(f"[+] Subdomain found: {green}{url.split('/')[2]}{reset}")
        except:
            pass
        q.task_done()
q = queue.Queue()

with open("wordlists/subdomain.txt", "r") as wordlist:
    for word in wordlist.read().splitlines():
        q.put(word)

for thread in range(threads):
    t = threading.Thread(target=brute, daemon=True, args=(thread,))
    t.start()

q.join()
