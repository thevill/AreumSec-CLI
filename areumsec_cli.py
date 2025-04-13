import os
from email import message_from_file
import glob
import re
import urllib.parse
import ipaddress
import dns.resolver
import dns.exception
import urllib.request
import json
from pathlib import Path
from urllib.parse import urlparse
import whois
from ipwhois import IPWhois
import hashlib
import requests

# Import API keys from config.py
try:
    from config import VIRUSTOTAL_API_KEY, SAFE_BROWSING_API_KEYS
except ImportError:
    print("Please add API keys")
    exit(1)

# If API keys are empty
if not VIRUSTOTAL_API_KEY or not SAFE_BROWSING_API_KEYS:
    print("Please add API keys")
    exit(1)

def check_ip_dnsbl(ip_address):
    dnsbls = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net",
            "xbl.spamhaus.org","z.mailspike.net","zen.spamhaus.org",
            "zombie.dnsbl.sorbs.net","multi.surbl.org","dnsbl.invaluement.com",
            "b.barracudacentral.org","bl.spamcop.net","blacklist.woody.ch",
            "bogons.cymru.com","cbl.abuseat.org","combined.abuse.ch","db.wpbl.info",
                          "dnsbl-1.uceprotect.net","dnsbl-2.uceprotect.net","dnsbl-3.uceprotect.net",
                          "dnsbl.dronebl.org","dnsbl.sorbs.net","drone.abuse.ch","duinv.aupads.org",
                          "dul.dnsbl.sorbs.net","dyna.spamrats.com","http.dnsbl.sorbs.net",
                          "ips.backscatterer.org","ix.dnsbl.manitu.net","korea.services.net",
                          "misc.dnsbl.sorbs.net","noptr.spamrats.com","orvedb.aupads.org",
                          "pbl.spamhaus.org","proxy.bl.gweep.ca","psbl.surriel.com",
                          "relays.bl.gweep.ca","relays.nether.net","sbl.spamhaus.org",
                          "singular.ttk.pte.hu","smtp.dnsbl.sorbs.net","socks.dnsbl.sorbs.net",
                          "spam.abuse.ch","spam.dnsbl.anonmails.de","spam.dnsbl.sorbs.net",
                          "spam.spamrats.com","spambot.bls.digibase.ca","spamrbl.imp.ch",
                          "spamsources.fabel.dk","ubl.lashback.com","ubl.unsubscore.com",
                          "virus.rbl.jp","web.dnsbl.sorbs.net","wormrbl.imp.ch"
    ]
    listed_dnsbls = []
    
    ip_version = ipaddress.ip_address(ip_address).version
    
    for dnsbl in dnsbls:
        try:
            if ip_version == 4:
                query = '.'.join(reversed(str(ip_address).split("."))) + "." + dnsbl
            else:
                query = '.'.join(reversed(str(ip_address).replace(':', ''))) + "." + dnsbl
            dns.resolver.resolve(query, 'A')
            listed_dnsbls.append(dnsbl)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.exception.DNSException as e:
            pass
    
    if listed_dnsbls:
        return f"listed in: {', '.join(listed_dnsbls)}"
    return "IP not listed in any of the DNSBLs"

def is_valid_path(path):
    return os.path.exists(path)

def is_valid_url(url):
    parsed_url = urllib.parse.urlparse(url)
    return parsed_url.scheme in ['http', 'https']

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_sha(input_str):
    sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')
    return sha256_pattern.match(input_str) is not None

def check_organization(sender_ip, sender_domain):
    if sender_ip is None:
        return "Unable to identify the organization from the IP/Domain"
    
    try:
        ip_valid = is_valid_ip(sender_ip)
        if not ip_valid:
            return "Invalid IP address"
        
        ip_version = ipaddress.ip_address(sender_ip).version
        ip_info = None
        
        if ip_version == 4:
            ip_info = whois.whois(sender_ip)
        else:
            try:
                ip = IPWhois(sender_ip)
                result = ip.lookup_rdap()
                ip_info = result.get('network', {}).get('name', '')
            except Exception as e:
                return f"Error fetching IPv6 organization information: {e}"
        
        domain_info = whois.whois(sender_domain)
        
        if not ip_info or not domain_info:
            return "Unable to identify the organization from the IP/Domain"
        
        ip_org = str(ip_info.get('org', '')).lower() if ip_version == 4 else ip_info.lower()
        domain_org = str(domain_info.get('org', '')).lower()
        
        if ip_org and domain_org and ip_org == domain_org:
            return "Sender IP and Domain belong to the same Organization"
        return "Sender IP and Domain does not belong to the same Organization"
    
    except Exception as e:
        return f"Error fetching WHOIS information: {e}"

def query_virustotal(url):
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url, 'allinfo': 'true'}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip, Python VT client"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
    json_response = response.json()
    
    if json_response['response_code'] == 1:
        verdict = f"The URL is {'malicious' if json_response['positives'] > 0 else 'not malicious'}."
        engines = json_response['scans']
        top_engines = sorted(engines.items(), key=lambda x: x[1]['detected'], reverse=True)[:5]
        engine_list = [f"{engine[0]}: {engine[1]['result']}" for engine in top_engines]
        return verdict, engine_list
    return f"Error: {json_response['verbose_msg']}"

def query_virustotal_sha(sha256):
    api_url = f'https://www.virustotal.com/api/v3/files/{sha256}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(api_url, headers=headers)
        url_info = response.json()
        
        if 'data' in url_info and 'attributes' in url_info['data'] and 'last_analysis_stats' in url_info['data']['attributes']:
            if url_info['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                return "SHA256 is Malicious"
            return "SHA256 is Safe"
        return "Unknown SHA256"
    
    except Exception as e:
        return f"Error querying VirusTotal API: {e}"

def encode_url(url):
    return urllib.parse.quote(str(url))

def calculate_sha256(file_path):
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(65536)
                if not data:
                    break
                sha256_hash.update(data)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating SHA256 hash: {e}")
        return None

def query_virustotal_file(file_path):
    sha256_hash = calculate_sha256(file_path)
    
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': sha256_hash, 'allinfo': 'true'}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip, Python VT client"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    json_response = response.json()
    
    if json_response['response_code'] == 1:
        verdict = f"The file is {'malicious' if json_response['positives'] > 0 else 'not malicious'}."
        engines = json_response['scans']
        top_engines = sorted(engines.items(), key=lambda x: x[1]['detected'], reverse=True)[:5]
        engine_list = [f"{engine[0]}: {engine[1]['result']}" for engine in top_engines]
        file_history = json_response.get('additional_info', {}).get('submissions', [])
        file_history_list = [f"Date: {entry['date']}, Verdict: {entry['result']}" for entry in file_history] if file_history else ["File submission history is not available."]
        return verdict, engine_list, file_history_list
    return f"Error: {json_response['verbose_msg']}"

def query_safe_browsing_url(file_path):
    for api_key in SAFE_BROWSING_API_KEYS:
        api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
        encoded_url = encode_url(file_path)
        
        payload = {
            'client': {
                'clientId': 'myapp',
                'clientVersion': '1.5.2'
            },
            'threatInfo': {
                'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': encoded_url}]
            }
        }
        
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(api_url, data=data, headers={'Content-Type': 'application/json'})
        
        try:
            with urllib.request.urlopen(req) as response:
                data = response.read().decode('utf-8')
                threat_info = json.loads(data)
                if threat_info.get('matches'):
                    return "URL matches known threats."
                return "URL does not match known threats."
        except Exception as e:
            print(f"Error querying Google Safe Browsing: {e}")
    
    return "Failed to check URL against Google Safe Browsing."

def extract_urls(file_path):
    urls = []
    file_extension = Path(file_path).suffix.lower()

    if file_extension in ['.eml', '.msg']:
        with open(file_path, 'r', encoding='utf-8') as file:
            msg = message_from_file(file)
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == 'text/plain' or content_type == 'text/html':
                        urls += re.findall(r'\bhttps?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)', part.get_payload())
            else:
                urls += re.findall(r'\bhttps?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)', msg.get_payload())
    elif file_extension == '.txt':
        with open(file_path, 'r', encoding='utf-8') as file:
            text = file.read()
            urls += re.findall(r'\bhttps?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)', text)
    return urls

def extract_subject(file_path):
    subject = ""
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension in ['.eml', '.msg', '.txt']:
        with open(file_path, 'r') as file:
            msg = message_from_file(file)
        subject = msg.get("Subject", "")
    return subject

def extract_sender_ip(file_path):
    sender_ip = ""
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension in ['.eml', '.msg', '.txt']:
        with open(file_path, 'r') as file:
            msg = message_from_file(file)
        headers = str(msg)
        ip_match = re.search(r'Received:.*\[(.*?)\]', headers)
        if ip_match:
            sender_ip = ip_match.group(1)
        else:
            return None
    return sender_ip

def extract_auth_data(file_path):
    with open(file_path, 'r') as file:
        msg = message_from_file(file)
        header = msg.get("Authentication-Results", "")
    if not header:
        return "No auth data found"
    spf_match = re.search(r'spf=([^\s;]+)', header)
    dkim_match = re.search(r'dkim=([^\s;]+)', header)
    dmarc_match = re.search(r'dmarc=([^\s;]+)', header)
    spf_value = spf_match.group(1) if spf_match else "SPF not found"
    dkim_value = dkim_match.group(1) if dkim_match else "DKIM not found"
    dmarc_value = dmarc_match.group(1) if dmarc_match else "DMARC not found"
    return {
        "SPF": spf_value,
        "DKIM": dkim_value,
        "DMARC": dmarc_value
    }

def extract_sender_info(file_path):
    p1_sender = ""
    p2_sender = ""
    sender_domain = ""
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension in ['.eml', '.msg', '.txt']:
        try:
            with open(file_path, 'r') as file:
                msg = message_from_file(file)
            p1_sender_headers = ["X-Mailfrom", "Return-path", "X-Original-Return-Path"]
            for header in p1_sender_headers:
                p1_sender = msg.get(header, "")
                if p1_sender:
                    break
            from_header = msg.get("From", "")
            if from_header:
                p2_sender = from_header.strip()
                sender_parts = p2_sender.split('@')
                if len(sender_parts) > 1:
                    sender_domain = sender_parts[1].split('>')[0].strip()
            return p1_sender, p2_sender, sender_domain
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    return "", "", ""

def process_file(file_path):
    results_list = []
    url_ver = ""
    orgnztn = ""
    
    if is_valid_path(file_path):
        if os.path.isdir(file_path):
            eml_files = glob.glob(os.path.join(file_path, '*.eml'))
            msg_files = glob.glob(os.path.join(file_path, '*.msg'))
            txt_files = glob.glob(os.path.join(file_path, '*.txt'))
            
            for email_file in eml_files + msg_files + txt_files:
                p1_sender, p2_sender, sender_domain = extract_sender_info(email_file)
                sender_ip = extract_sender_ip(email_file)
                subject = extract_subject(email_file)
                urls = extract_urls(email_file)
                url_ver = query_safe_browsing_url(urls[0]) if urls else "No URLs found"
                orgnztn = check_organization(sender_ip, sender_domain)
                
                results = {
                    "File": email_file,
                    "P1Sender": p1_sender,
                    "P2Sender": p2_sender,
                    "Sender Domain": sender_domain,
                    "Subject": subject,
                    "Sender IP Address": sender_ip if sender_ip else "Not found",
                    "Authentication results": extract_auth_data(email_file),
                    "URLs": [urlparse(url).geturl() for url in urls] if urls else "No URLs found",
                    "Open Threat Intel Summary": {
                        "Organization": orgnztn,
                        "URL": [urlparse(url).geturl() for url in urls] if url_ver == "URL matches known threats." else "No URLs were flagged as malicious.",
                        "IP": "Sender IP Address: Not found" if sender_ip is None else check_ip_dnsbl(sender_ip),
                    },
                    "Open Threat Intel Verdict": (
                        "Looks suspicious." if (
                            url_ver == "URL matches known threats." and "listed in:" in check_ip_dnsbl(sender_ip) if sender_ip else False
                        ) or (
                            url_ver == "URL matches known threats." and orgnztn == "Sender IP and Domain does not belong to the same Organization"
                        ) or (
                            orgnztn == "Sender IP and Domain does not belong to the same Organization" and "listed in:" in check_ip_dnsbl(sender_ip) if sender_ip else False
                        ) else "Might be good"
                    ),
                }
                results_list.append(results)
                print(results)
        
        elif os.path.isfile(file_path):
            file_extension = os.path.splitext(file_path)[1].lower()
            if file_extension in ['.msg', '.eml', '.txt']:
                p1_sender, p2_sender, sender_domain = extract_sender_info(file_path)
                sender_ip = extract_sender_ip(file_path)
                subject = extract_subject(file_path)
                urls = extract_urls(file_path)
                url_ver = query_safe_browsing_url(urls[0]) if urls else "No URLs found"
                orgnztn = check_organization(sender_ip, sender_domain)
                
                results = {
                    "File": file_path,
                    "P1Sender": p1_sender,
                    "P2Sender": p2_sender,
                    "Sender Domain": sender_domain,
                    "Subject": subject,
                    "Sender IP Address": sender_ip if sender_ip else "Not found",
                    "Authentication results": extract_auth_data(file_path),
                    "URLs": [urlparse(url).geturl() for url in urls] if urls else "No URLs found",
                    "Open Threat Intel Summary": {
                        "Organization": orgnztn,
                        "URL": [urlparse(url).geturl() for url in urls] if url_ver == "URL matches known threats." else "No URLs were flagged as malicious.",
                        "IP": "Sender IP Address: Not found" if sender_ip is None else check_ip_dnsbl(sender_ip),
                    },
                    "Open Threat Intel Verdict": (
                        "Looks suspicious." if (
                            url_ver == "URL matches known threats." and "listed in:" in check_ip_dnsbl(sender_ip) if sender_ip else False
                        ) or (
                            url_ver == "URL matches known threats." and orgnztn == "Sender IP and Domain does not belong to the same Organization"
                        ) or (
                            orgnztn == "Sender IP and Domain does not belong to the same Organization" and "listed in:" in check_ip_dnsbl(sender_ip) if sender_ip else False
                        ) else "Might be good"
                    ),
                }
                results_list.append(results)
                print(results)
            else:
                gsb_analysis = query_virustotal_file(file_path)
                print("\nVirusTotal analysis:")
                if isinstance(gsb_analysis, tuple):
                    verdict, engine_list, file_history_list = gsb_analysis
                    print(verdict)
                    print("Top 5 engines:")
                    for engine in engine_list:
                        print(engine)
                    print("File submission history:")
                    for entry in file_history_list:
                        print(entry)
                else:
                    print(gsb_analysis)
    
    elif is_valid_url(file_path):
        vt_analysis = query_virustotal(file_path)
        print("\nVirusTotal analysis:")
        if isinstance(vt_analysis, tuple):
            verdict, engine_list = vt_analysis
            print(verdict)
            print("Top 5 engines:")
            for engine in engine_list:
                print(engine)
        else:
            print(vt_analysis)
        gsb_analysis = query_safe_browsing_url(file_path)
        print("\nSafe Browsing analysis:", gsb_analysis)
    
    elif is_valid_ip(file_path):
        ip_check = check_ip_dnsbl(file_path)
        print("IP analysis:", ip_check)
    
    elif is_sha(file_path):
        sha_analysis = query_virustotal_sha(file_path)
        print("\nVirusTotal analysis:", sha_analysis)
    
    else:
        print("Invalid input.")

# Input
print("\nWelcome to AreumSec-CLI")
print("\nAreumSec-CLI is a real-time cybersecurity threat analysis application built with Python. \nDesigned for security analysts and VAPT professionals, for rapid file, URL, and IP/hash investigations.")
print("\n--Developed by Pranay Wajjala--")
c_input = input("\nPlease provide an input: ")
process_file(c_input)