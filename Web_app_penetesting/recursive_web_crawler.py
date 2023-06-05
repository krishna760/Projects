from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
import sys
import queue
import threading

domain = sys.argv[1]
thr = int(sys.argv[2])

q = queue.Queue()
q.put(domain)

visited = set()  # Set to store visited URLs

def crawl(tno):
    while not q.empty():
        domain = q.get()
        try:
            response = requests.get(domain, allow_redirects=True, timeout=2)
            response.encoding = response.apparent_encoding  # Set the appropriate encoding
            soup = BeautifulSoup(response.text, "html.parser")
            for a in soup.find_all('a', href=True):
                link = urljoin(domain, a['href'])
                if '#' in link:
                    link = link.split('#')[0]

                if domain.split('/')[2] in link and link not in visited:
                    visited.add(link)  # Add the URL to visited set
                    print(link)
                    with open(f"{domain.split('/')[2]}.txt", 'a') as file:
                        file.write(link + '\n')
                    q.put(link)
        except KeyboardInterrupt:
            exit(0)
        except (requests.RequestException, ValueError):
            pass

threads = []
for t in range(thr):
    thread = threading.Thread(target=crawl, args=(t,))
    thread.start()
    threads.append(thread)

# Wait for all threads to finish
for thread in threads:
    thread.join()
