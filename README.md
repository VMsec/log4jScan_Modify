<h1 align="center">log4j-scan</h1>
<h4 align="center">A fully automated, accurate, and extensive scanner for finding vulnerable log4j hosts</h4>

![](https://dkh9ehwkisc4.cloudfront.net/static/files/80e52a5b-7d72-44c2-8187-76a2a58f5657-demo.png)

# 🚨 免责声明

本项目仅面向合法授权的企业安全建设行为，在使用本项目进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。

如您在使用本项目的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在使用本项目前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。

除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本项目。

您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

# 修改

payload的拼接逻辑

修改为多线程发包

修改payload只使用ladp回连，省掉无用发包

只使用ldap监听器记录，放弃了dnslog验证（为了效率）

# 使用

```
python3 log4j-scan.py -l all_active_webs.txt --run-all-tests  --waf-bypass --custom-dns-callback-host 1.1.1.1:1389
```

# 设置监听

参考：https://github.com/r00tSe7en/JNDIMonitor

---
# Announcement

There is a patch bypass on Log4J v2.15.0 that allows a full RCE. FullHunt added community support for log4j-scan to reliably detect CVE-2021-45046. If you're having difficulty discovering and scanning your infrastructure at scale or keeping up with the Log4J threat, please get in touch at (team@fullhunt.io).

![](https://dkh9ehwkisc4.cloudfront.net/static/files/d385f9d8-e2b1-4d72-b9c2-a62c4c1c34a0-Screenshot-cve-2021-45046-demo.png)

---

# Description

We have been researching the Log4J RCE (CVE-2021-44228) since it was released, and we worked in preventing this vulnerability with our customers. We are open-sourcing an open detection and scanning tool for discovering and fuzzing for Log4J RCE CVE-2021-44228 vulnerability. This shall be used by security teams to scan their infrastructure for Log4J RCE, and also test for WAF bypasses that can result in achieving code execution on the organization's environment.

It supports DNS OOB callbacks out of the box, there is no need to set up a DNS callback server.




# Usage

```python
$ python3 log4j-scan.py -h
[•] CVE-2021-44228 - Apache Log4j RCE Scanner
[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
[•] Secure your External Attack Surface with FullHunt.io.
usage: log4j-scan.py [-h] [-u URL] [-p PROXY] [-l USEDLIST] [--request-type REQUEST_TYPE] [--headers-file HEADERS_FILE] [--run-all-tests] [--exclude-user-agent-fuzzing]
                     [--wait-time WAIT_TIME] [--waf-bypass] [--custom-waf-bypass-payload CUSTOM_WAF_BYPASS_PAYLOAD] [--test-CVE-2021-45046]
                     [--dns-callback-provider DNS_CALLBACK_PROVIDER] [--custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST] [--disable-http-redirects]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Check a single URL.
  -p PROXY, --proxy PROXY
                        send requests through proxy
  -l USEDLIST, --list USEDLIST
                        Check a list of URLs.
  --request-type REQUEST_TYPE
                        Request Type: (get, post) - [Default: get].
  --headers-file HEADERS_FILE
                        Headers fuzzing list - [default: headers.txt].
  --run-all-tests       Run all available tests on each URL.
  --exclude-user-agent-fuzzing
                        Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.
  --wait-time WAIT_TIME
                        Wait time after all URLs are processed (in seconds) - [Default: 5].
  --waf-bypass          Extend scans with WAF bypass payloads.
  --custom-waf-bypass-payload CUSTOM_WAF_BYPASS_PAYLOAD
                        Test with custom WAF bypass payload.
  --test-CVE-2021-45046
                        Test using payloads for CVE-2021-45046 (detection payloads).
  --dns-callback-provider DNS_CALLBACK_PROVIDER
                        DNS Callback provider (Options: dnslog.cn, interact.sh) - [Default: interact.sh].
  --custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST
                        Custom DNS Callback Host.
  --disable-http-redirects
                        Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have a higher chance of reaching vulnerable systems.
```

## Scan a Single URL

```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local
```

## Scan a Single URL using all Request Methods: GET, POST (url-encoded form), POST (JSON body)


```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local --run-all-tests
```

## Discover WAF bypasses against the environment.

```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local --waf-bypass
```

## Scan a list of URLs

```shell
$ python3 log4j-scan.py -l urls.txt
```

# Installation

```
$ pip3 install -r requirements.txt
```

# Docker Support

```shell
git clone https://github.com/fullhunt/log4j-scan.git
cd log4j-scan
sudo docker build -t log4j-scan .
sudo docker run -it --rm log4j-scan

# With URL list "urls.txt" in current directory
docker run -it --rm -v $PWD:/data log4j-scan -l /data/urls.txt
```

# About FullHunt

FullHunt is the next-generation attack surface management platform. FullHunt enables companies to discover all of their attack surfaces, monitor them for exposure, and continuously scan them for the latest security vulnerabilities. All, in a single platform, and more.

FullHunt provides an enterprise platform for organizations. The FullHunt Enterprise Platform provides extended scanning and capabilities for customers. FullHunt Enterprise platform allows organizations to closely monitor their external attack surface, and get detailed alerts about every single change that happens. Organizations around the world use the FullHunt Enterprise Platform to solve their continuous security and external attack surface security challenges.

# Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of log4j-scan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.


# License
The project is licensed under MIT License.


# Author
*Mazin Ahmed*
* Email: *mazin at FullHunt.io*
* FullHunt: [https://fullhunt.io](https://fullhunt.io)
* Website: [https://mazinahmed.net](https://mazinahmed.net)
* Twitter: [https://twitter.com/mazen160](https://twitter.com/mazen160)
* Linkedin: [http://linkedin.com/in/infosecmazinahmed](http://linkedin.com/in/infosecmazinahmed)
