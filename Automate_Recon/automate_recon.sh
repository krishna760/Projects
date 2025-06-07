#!/usr/bin/env bash

#Bug Hunting Recon Automation Script
echo "Fork it on https://github.com/CalfCrusher/RobinHood and make World a better place"
# Save starting execution time
start=`date +%s`

GITHUB_API_KEY="<apikey>" #Github api key foe github.py(EDIT THIS)
GITHUB_SUBDOMAIN="/home/krish500/github_subdomain.py" #Github subdomain finder (EDIT THIS)
CENSYS_API_ID="<apikey>" # Censys api id for CloudFlair(EDIT THIS)
CENSYS_API_SECRET="<apikey>" # Censys api secret for CloudFlair (EDIT THIS)
CENSYS_SUBDOMAIN_FINDER="/home/krish500/censys-subdomain-finder/censys-subdomain-finder.py" #CENSUS SUBDOMAIN FINDER PATH (EDIT THIS)
CLOUDFLAIR="/home/krish500/cloudflair/cloudflair.py" # Path for CloudFlair tool location (EDIT THIS)
VULSCAN_NMAP_NSE="/usr/share/nmap/scripts/vulners.nse" # Vulscan NSE script for Nmap (EDIT THIS)
JSUBFINDER_SIGN=".jsf_signatures.yaml" # Path signature location for jsubfinder (EDIT THIS)
LINKFINDER="/home/krish500/linkfinder.py" # Path for LinkFinder tool (EDIT THIS)
FINGERPRINTS="/home/krish500/Programs/wordlists/fingerprints.json" #path for fingerprints.json for subjack
VHOSTS_SIEVE="/home/krish500/vhosts-sieve/vhosts-sieve.py" # Path for VHosts Sieve tool (EDIT THIS)
CLOUD_ENUM="/home/krish500/cloud_enum/cloud_enum.py" # Path for cloud_enum tool, Multi-cloud OSINT tool (EDIT THIS)
XFORWARDY="/home/krish500/xforwardy/xforwardy.py" #for host header injection"
ALTDNS_WORDS="/home/krish500/Programs/wordlists/altdns.txt" # Path to altdns words permutations file (EDIT THIS)
DNSREAPER="/home/krish500/dnsReaper/main.py" # Path to dnsrepaer tool (EDIT THIS)
ORALYZER="/home/krish500/Oralyzer/oralyzer.py" # Oralyzer path url tool (EDIT THIS)
ORALYZER_PAYLOADS="/home/krish500/Oralyzer/payloads.txt" # Oralyzer payloads file (EDIT THIS)
SMUGGLER="/home/krish500/smuggler/smuggler.py" # Smuggler tool (EDIT THIS)
PARAMS="/home/krish500/wordlists/params.txt" # List of params for bruteforcing GET/POST hidden params (EDIT THIS)
# LFI_PAYLOADS="/home/krish500/wordlists/lfi_payload" # List of payloads for LFI
# PARAMSPIDER="/home/krish500/ParamSpider/paramspider.py" # Path to paramspider tool (EDIT THIS)
# TPLMAP="/home/krish500/tplmap/tplmap.py" #for ssti finding

JSUBFINDER=$(command -v jsubfinder)
SUBJS=$(command -v subjs)
URO=$(command -v uro)

HOST=$1
trap 'handle_ctrl_c' SIGINT
handle_ctrl_c() {
    echo
    read -p "Ctrl+C caught! Exit? (y/n): " choice
    if [[ $choice == "y" ]]; then
        exit 0
    else
        echo ''
    fi
}

echo ''
echo ''
echo '* Subdomains Enumeration...'
echo ''
echo ''

#https://pentest-tools.com/information-gathering/find-subdomains-of-domain gives more..
#Utilizing machine learning to collect more subdomains
#./wizsub.sh woox.io x ~/AUTOHUNT/subdomains_woox.io.txt 5000 //
# Subdomains Enumeration
source ~/myenv/bin/activate
echo '----Sublist3r----'
sublist3r -d $HOST -o subdomains_$HOST.txt
deactivate
source ~/.bashrc
echo '----Subfinder----'
subfinder -d $HOST -all -recursive -silent | awk -F[ ' {print $1}' | tee -a subdomains_$HOST.txt
echo '----AMASS----'
#amass enum -passive -d $HOST | tee -a subdomains_$HOST.txt
echo '----findomain----'
findomain -t $HOST  -q --exclude-sources crtsh| tee -a subdomains_$HOST.txt
echo '----Assetfinder----'
assetfinder -subs-only $HOST | tee -a subdomains_$HOST.txt
echo '----CRT.SH----'
curl -s "https://crt.sh/?q=%.$HOST&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | awk -F '\' '{print $1}' | tee -a subdomains_$HOST.txt
echo '----Github----'
github-subdomains -d $HOST -t $GITHUB_API_KEY -o subdomain_$HOST.txt
cat subdomain_$HOST.txt | tee -a subdomains_$HOST.txt
rm subdomain_$HOST.txt
echo '----CENSYS_SUBDOMAIN----'
source ~/Programs/censys-subdomain-finder/venv/bin/activate
cd ~/Programs/censys-subdomain-finder
python3 censys-subdomain-finder.py --censys-api-id CENSYS_API_ID --censys-api-secret CENSYS_API_SECRET $HOST | awk -F " " '{print $2}' | tee -a ~/AUTOHUNT/subdomains_$HOST.txt
cd ~/AUTOHUNT
bbot -t $HOST --silent -p subdomain-enum -o subdomain
cat subdomain/*/subdomains.txt >> subdomains_$HOST.txt
deactivate
cat subdomains_$HOST.txt > subdomain.txt
rm subdomains_$HOST.txt
cat subdomain.txt | sort -u | grep -i $HOST | tee subdomains_$HOST.txt
rm subdomain.txt
echo ''
echo ''
#echo '* Adding more subdomains using permutation (AltDNS) ..'
echo ''
echo ''

#Add more Subdomains using permutations with Altdns and puredns
source ~/myenv/bin/activate
altdns -i subdomains_$HOST.txt -o temp_output -w ~/Programs/wordlists/altdns.txt
cat temp_output|wc
mkdir puredns
cat temp_output | puredns  resolve -r ~/Programs/wordlists/resolvers.txt --write puredns/valid_domains.txt  --write-wildcards puredns/wildcards.txt  --write-massdns puredns/massdns.txt
rm temp_output
puredns bruteforce ~/Programs/wordlists/altdns.txt -d subdomains_$HOST.txt --write puredns/valid_domains1.txt
cat puredns/valid_domains1.txt puredns/valid_domains.txt >> subdomains_$HOST.txt
cat subdomains_$HOST.txt|sort -u>>sub
rm subdomains_$HOST.txt; cat sub >> subdomains_$HOST.txt
rm puredns/valid_domains1.txt; rm sub
deactivate

echo ''
echo ''
echo 'Scanning PORT using rust---'
echo ''
echo ''
cat subdomains_$HOST.txt | httprobe -c 50 > httprobe_output_$HOST.txt
cat subdomains_$HOST.txt | httpx -sc -td -server -cdn -method -probe -title -fr -ip -method -silent|tee -a httpx_output$HOST.txt
cat subdomains_$HOST.txt | xargs -I {} sudo docker run --rm --name rustscan rustscan/rustscan:2.1.1 --addresses {} --accessible --ulimit 4000 -r 1-65535 -b 4000| tee -a openport_$HOST.txt
##In open port run
##nmap -sV -oN -O nmap_results_$HOST.txt -iL http_$HOST.txt --script=/usr/share/nmap/scripts/vulners.nse -F -—max-rate 1000


echo ''
echo '---Play with ip---'
echo ''
# gungnir -r watch -f   (continuously monitors certificate transparency (CT) logs for newly issued SSL/TLS certificates. Primary purpose isto discovering new domains and subdomains as soon as they are issued certificates, allowing for timely security testing)
source ../myenv/bin/activate
cat subdomains_$HOST.txt | dnsx -silent -a -resp >> ip.txt
cat subdomains_$HOST.txt | dnsx -silent -a -resp >> ip.txt
cat subdomains_$HOST.txt | dnsx -silent -a -resp >> ip.txt
cat subdomains_$HOST.txt | dnsx -silent -a -resp >> ip.txt
cat subdomains_$HOST.txt | dnsx -silent -a -resp >> ip.txt
cat subdomains_$HOST.txt | dnsx -silent -a -resp >> ip.txt
cat ip.txt |sort -u >> ip2.txt
cat ip2.txt|awk -F " " '{print $3}'| sed 's/\[//;s/\]//'| sed 's/\x1b\[[0-9;]*m//g' |sort -u  >> ips.txt; rm ip2.txt; rm ip.txt
caduceus -i ips.txt -j |python3 ~/Programs/harpy.py |tee -a map_ip_to_cert_$HOST.txt
deactivate
cat ips.txt | dnsx -silent -resp-only -ptr >> ptr.record_$HOST.txt
cat ips.txt |httpx -sc -td -fr  -title -cdn >>httpx_ips_$HOST.txt
#imp for subdoamin takeover
cat subdomains_$HOST.txt |dnsx -silent -cname -resp  >>cnameOf_HOST.txt
source ../myenv/bin/activate
#echo 173.0.84.0/24 | tlsx -san -cn -silent -resp-only | dnsx -silent | httpx
#cat subdomains_$HOST.txt | tlsx -san -cn -silent -resp-only | dnsx -silent | httpx

echo '--EXTRACTING DOMAIN FROM CERTIFICATE---'
caduceus -i  ips.txt -c 50 >> caduceus_output.txt
caduceus -i  subdomains_$HOST.txt -c 50 >> caduceus_output.txt
cat ips.txt | tlsx -san -silent -resp-only >> tlsx_output.txt
cat subdomains_$HOST.txt| tlsx -san -silent -resp-only >> tlsxsub_output.txt
cat caduceus_output.txt tlsx_output.txt tlsxsub_output.txt|sort -u >>  san.record_$HOST.txt #Subject Alternative Name
deactivate
cat san.record_$HOST.txt | dnsx -silent |httpx -status-code -fr -td -title |tee -a resolveCert_to_ip$HOST.txt #new subdomain
source /home/krish500/myenv/bin/activate
rm caduceus_output.txt; rm tlsx_output.txt; rm tlsxsub_output.txt

tlsx -l ips.txt -expired -self-signed -mismatched -revoked -untrusted | tee -a Maybefaulty_cert_$HOST.txt
tlsx -l subdomains_$HOST.txt -expired -self-signed -mismatched -revoked -untrusted | tee -a Maybefaulty_cert_$HOST.txt



echo ''
echo '--------Finding interesting SUBDOMAIN & Favbreak--------'
echo ''
echo ''
#cat subdomains_$HOST.txt | while read -r domain; do ip=$(dig +short "$domain"); [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "$domain-$ip" >> domains_with_ips.txt; done
#cat domains_with_ips.txt|awk -F "-" "{print $2}" >>ips.txt
deactivate
cat ips.txt|httprobe>>HttpIP.txt
cat httprobe_output_$HOST.txt HttpIP.txt | httpx > httpx.txt
rm HttpIP.txt
source /home/krish500/myenv/bin/activate
cat httpx.txt | python3 ../Programs/FavFreak/favfreak.py --shodan | tee -a favicon_hash.txt
rm httpx.txt
deactivate

#echo ''
#echo ''
#echo '* Try to bypass 403 and 401 status code with nowaf'
#echo ''
#echo ''
#cat httpx_output$HOST.txt | grep -v -i -E 'cloudfront|imperva|cloudflare' >> nowaf_$HOST.txt
#cat nowaf_$HOST.txt | grep 403 | awk '{print $1}' >> nowaf_403_$HOST.txt
source /home/krish500/myenv/bin/activate
#TRY to bypass 403 with  ~/Programs/4-ZERO-3/./403-bypass.sh
#python3 wafbypasser.py https://$HOST
#Open Multiple URLs for quicker manual investigation using domain in nowaf_403_$HOST.txt
#Then fuzz this 403 domain using ffuff and try tobypass this endpoint using script file ...

#echo 'IMP for URL validation --- https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet ---BYPASS which can chain with different attack---'


echo ''
echo ''
echo '* Fuzzing CRLF vulnerabilities ..'
echo ''
echo ''

# Fuzzing CRLF vulnerabilities
#cat subdomains_$HOST.txt | httprobe |crlfuzz -v | tee -a crlfuzz_results_$HOST.txt

echo ''
echo ''
echo '* Searching for subdomains takeover ..'
echo ''
echo ''

subjack -w subdomains_$HOST.txt -t 100 -c $FINGERPRINTS -v | tee -a subtakeover_subjack_$HOST
source ~/myenv/bin/activate
python3 ~/Programs/dnsReaper/main.py file --filename subdomains_$HOST.txt |tee -a subtakeover_dnsreaper_$HOST
deactivate
subzy run --targets subdomains_$HOST.txt --concurrency 100 --hide_fails --verify_ssl | tee -a subtakeover_subzy_$HOST


# Run ParamSpider(NOT WORKING)
#source ~/myenv/bin/activate
#python3 $PARAMSPIDER --domain $HOST --exclude woff,css,png,svg,jpg --quiet
#cat output/$HOST.txt | $URO | tee paramspider_results_$HOST.txt
#rm -rf output/

echo ''
echo ''
echo '* Getting all urls using Gau ..'
echo ''
echo ''

# Get URLs with gau
echo $HOST |  gau | tee -a all_urls_$HOST.txt
source /home/krish500/myenv/bin/activate
waymore -i $HOST -mode U -oU waymore.txt
cat waymore.txt >>  all_urls_$HOST.txt
rm waymore.txt
deactivate
#VERY SLOW so do it manually
#nuclei -l livejs$HOST.txt -t nuclei-templates/http/exposures -o potential_secrets.txt
echo ''
echo ''
echo '* Spidering live subdomains using Katana to add more urls ..'
echo ''
echo ''

# Get URLs with katana
katana -list subdomains_$HOST.txt -d 4 -ef png,jpg,gif,jpeg,woff,svg,css -nc -ct 1800 -silent -c 5 -p 2 -rl 50 -o katana_urls_$HOST.txt
# Add new spidered urls to full list
cat katana_urls_$HOST.txt >> all_urls_$HOST.txt
source ~/myenv/bin/activate
cat all_urls_$HOST.txt | sort -u | uro|grep "$HOST">> urls_$HOST.txt
rm all_urls_$HOST.txt
mv urls_$HOST.txt all_urls_$HOST.txt
deactivate
#finding live js_endpoint

mkdir txtfile
cat all_urls_$HOST.txt| grep '\.js'|sed 's|\?.*||' >> txtfile/js.txt
#cat txtfile/js.txt|httpx -sc -fr|grep '200|201|500|403|401' | awk '{print $1}' >> livejs$HOST.txt
echo ''
echo ''
echo '* Searching for secrets in javascript files ..'
echo ''
echo ''

# Search for secrets
#jsubfinder search -f live_subdomains_$HOST.txt -s jsubfinder_secrets_$>

# Remove file if empty
#if [ ! -s jsubfinder_secrets_$HOST.txt ]
#then
#    rm jsubfinder_secrets_$HOST.txt
#fi

#MY method
cat all_urls_$HOST.txt | grep -E "\.sql|\.log|\.bak|\.php|\.aspx|\.apk|\.asp|\.jsp|\.jspx|\.aspx|\.txt|\.cache|\.secret|\.db|\.backup|\.yaml|\.yml|\.json|\.gz|\.rar|\docx|\.doc|\.zip|\.config|\.7z|\.git|\.sh|\.zi|\.ex|\.7|\.ini|\.cfg|\.xml|\.asc|\.env|\.crt|\.cert|\.rpm|\.sh|\.iso|\.tf|\.dockerfile|\.pptx|\.dll|\.bat|\.tar|\.har|\.wadl|\.wsdl|\.swp|\.old|\.tmp|\.sqlite|\.md|\.md5|\.exe|\.mdb|\.pem|\.msi|\.key|\.htpasswd|\.htaccess|\.der|\.rdp|\.conf|\.resx|\.encrc|\.bashrc|\.zshrc|\.profile|\.lst|\.sln|\.circleci|\.kubeconfig|\.vault|\.jks|\.ppk|\.pem|\.keytab|\.z|\.xz|\.tgz|\.arj|\.cab|\.psql|\.ndb|\.cfm|\.wsf|\.shtm|\.lck|\.pac|.\pub"| anew txtfile/interesting_fileinUrls$HOST.txt
cat all_urls_$HOST.txt | grep '?'     | anew params_endpoints_urls_$HOST.txt
#for i in $(cat reflected.txt); do (python3 $TPLMAP -u ${i}); done | anew SSTIof$HOST.txt
#nmap -p 80,443 --script=http-enum miro.com
echo ''
echo ''
echo '# Wordlist generate..'
mkdir custom_wordlist
cat all_urls_$HOST.txt | tok -delim-exceptions=- | sort -u | tee geneterated-wordlist$HOST.txt
cat all_urls_$HOST.txt | unfurl -u keys | tee -a custom_wordlist/key_$HOST.txt
cat all_urls_$HOST.txt | unfurl -u paths | tee -a path.txt; sed 's#/#\n#g' path.txt | sort -u | tee -a custom_wordlist/path$HOST.txt
cat custom_wordlist/key_$HOST.txt; cat custom_wordlist/path_$HOST.txt | sort -u; rm path.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' geneterated-wordlist$HOST.txt |tee -a custom_wordlist/geneterated-wordlist$HOST.txt

echo ''
echo ''
echo '* Discovering secret in JS urls ..'
echo ''
echo ''
source ~/myenv/bin/activate
for url in $(cat txtfile/js.txt); do (python3 ~/Programs/secretfinder/SecretFinder.py  -i "$url" -o cli| tee -a secretfinder_$HOST.txt); done
#IF Map apikey found then scan for its validity
#python3 ~/Programs/maps_api_scanner.py

#DOM-based vulnerabilities require you to look for DOM sinks and sources
#location.hash, eval, location.href or innerHTML
#best tool DOM Invader by portswigger

#VULN in old js
#for URL in $(cat ~/AUTOHUNT/js.txt); do ( python3 ~/Programs/jshole/jshole.py -u $URL); done
#Ensure u r in ~/Programs/jshole folder
echo ''
echo '---Find unsafe functio---'
for url in $(cat txtfile/js.txt); do (python3 ~/Programs/unsafefunc_detection.py  -j $url);done |tee -a unsafefunc_$HOST.tct

echo ''
echo ''
echo '* Discovering endpoints in JS urls ..'
echo ''
echo ''

# Discover endpoints in javascript urls
for URL in $(<txtfile/js.txt); do (python3 ~/Programs/LinkFinder/linkfinder.py -i $URL -o cli | tee -a linkfinder_results_$HOST.txt); done
deactivate

echo ''
echo ''
#echo '* Running Nuclei on all live subdomains ..'
echo ''
echo ''

#VERY SLOW
# Run Nuclei and run accod to framework
#$NUCLEI  -list live_subdomains$HOST.txt -o nuclei_results_$HOST.txt -c 5
#$NUCLEI -l -list live_subdomains$HOST.txt -t ~/cent-nuclei-templates | tee -a nuclei_results_$HOST.txt

echo ''
echo ''
#echo '* Extract possible cloudflare hosts and try to get origin ip ..'
echo ''
echo ''

source /home/krish500/myenv/bin/activate
~/Programs/ShodanSpider/./shodanspider.sh -q $HOST |tee -a shodan_ip_$HOST.txt
deactivate
cat shodan_ip_$HOST.txt  |httpx -sc -td -server -cdn -method -probe -title -fr -ip -method -silent  -cname -extract-fqdn|tee -a httpx_result_of_shodanip_$HOST.txt
source /home/krish500/myenv/bin/activate
python3 ~/Programs/HostHunter/hosthunter.py   shodan_ip_$HOST.txt

#MANUAL METHOD
#nano  ~/Programs/finding_origin_ip.txt


# Extracting urls with possible XSS params ..
cat params_endpoints_urls_$HOST.txt |gf xss| uro | Gxss |kxss |tee -a unfiltered_caracter_xss_$HOST.txt
cat unfiltered_caracter_xss_$HOST.txt | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > finalxss_$HOST.txt
deactivate
#TEST XSS
#source /home/krish500/myenv/bin/activate
#python3 ~/Programs/loxs/loxs.py
#Enter the path to the input file containing URLs (or press Enter to enter a single URL): /home/krish500/AUTOHUNT/finalxss_$HOST.txt
#Enter the path to the payloads file:  /home/krish500/Programs/loxs/payloads/xss.txt
#deactivate

#Extracting urls with possible SQL params and run sqlmap ..
#python3 ~/Programs/sqlmap-dev/sqlmap.py -m sqli_urls_$HOST.txt -v 3 --level=5 --risk=3 --tamper="between,randomcase" --delay=2 --threads=2 --smart  --random-agent --output-dir=sqlmap_$HOST

echo ''
echo ''
echo '* Extracting urls with possible OPEN Redirect params and run Oralyzer ..'
echo ''
echo ''

# Extract urls with possible OPEN REDIRECT params
cat params_endpoints_urls_$HOST.txt | gf redirect > redirect_urls_$HOST.txt
source ~/myenv/bin/activate
python3 ~/Programs/Oralyzer/oralyzer.py -l redirect_urls_$HOST.txt -p ~/Programs/Oralyzer/payloads.txt |tee -a oralyzer_results_$HOST.txt

echo ''
echo ''
echo '* Searching for vhosts ..'
echo ''
echo ''

# Searching for virtual hosts
python3 ~/Programs/vhosts-sieve/vhosts-sieve.py -v -d subdomains_$HOST.txt -o vhost_$HOST.txt|tee -a vhost_$HOST.txt

echo ''
echo ''
echo '* Searching for public resources in AWS, Azure, and Google Cloud, firebase, Google App Engine ..'
echo ''
echo ''

# Searching for public resources in AWS, Azure, and Google Cloud
KEYWORD=$(echo ${HOST} | cut -d"." -f1)
python3 ~/Programs/cloud_enum/cloud_enum.py  -k $HOST -k $KEYWORD -l cloud_enum_$HOST.txt
deactivate

echo ''
echo ''
echo '* HTTP Request Smuggling CRLF on all live subdomains ..'
echo ''
echo ''

# Run Smuggler, a HTTP Request Smuggling / Desync testing tool
cat subdomains_$HOST.txt | python3 ~/Programs/smuggler/smuggler.py  -q -l smuggler_results_$HOST.txt

# Save finish execution time
end=`date +%s`
echo ''
echo ''
echo ''
echo "********* COMPLETED ! *********"
echo ''
echo "Fork it on https://github.com/CalfCrusher/RobinHood and make World a better place"
echo ''
echo Execution time was `expr $end - $start` seconds
