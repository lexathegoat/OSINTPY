# OSINTPY

OSINT tool for domain, network, and social media reconnaissance.

## Features

- WHOIS lookup
- Subdomain enumeration (crt.sh)
- DNS records (A, MX, NS, TXT, etc.)
- IP geolocation
- Shodan host scan
- SSL certificate details
- Website tech stack (Wappalyzer)
- Recursive email harvesting
- Port scanning
- Telegram user/channel/group profile
- Twitter (X) user profile
- Multi-platform username search

## Installation

```bash
pip install requests python-whois dnspython beautifulsoup4 wappalyzer-python shodan pyOpenSSL
```

## Usage 
```bash
python osintpy.py <target> <module>
```

## Examples 
```bash

python osintpy.py x list #list modules
```
```bash

python osintpy.py example.com whois #domain WHOIS
```
```bash
python osintpy.py example.com subdomaincrt #subdomains
```
```bash
python osintpy.py example.com all #full scan
```
```bash

python osintpy.py lexathegoat socialusernamesearch #social username search
```
```bash
python osintpy.py lexathegoat telegram #telegram user
```
```bash
python osintpy.py example.com email_harvester 2 #email harvest depth 2
```
