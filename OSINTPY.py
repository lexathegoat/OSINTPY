import requests
import json
import sys
import re
import time
from urllib.parse import urlparse, quote, urljoin
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor
import socket
import dns.resolver
import whois
import shodan
import censys.certificates
from wappalyzer import Wappalyzer, WebPage
import OpenSSL.crypto
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

class OSINTPY:
    def __init__(self, api_keys=None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        self.api_keys = api_keys or {}
        self.wappalyzer = Wappalyzer.latest()

    def domain_whois(self, domain):
        try:
            w = whois.whois(domain)
            return {
                'domain': domain,
                'registrar': w.registrar,
                'registrant': w.get('name') or w.get('registrant_name'),
                'organization': w.get('org') or w.get('registrant_organization'),
                'email': w.email,
                'phone': w.get('phone'),
                'address': w.address,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': w.name_servers,
                'status': w.status
            }
        except Exception as e:
            return {'error': str(e)}

    def subdomain_enum_crtsh(self, domain):
        try:
            url = f'https://crt.sh/?q=%25.{domain}&output=json'
            response = self.session.get(url, timeout=30)
            data = response.json()
            subs = set()
            for entry in data:
                name = entry['name_value'].lower()
                if domain in name:
                    subs.add(name.strip('*'))
            return list(subs)
        except Exception as e:
            return {'error': str(e)}

    def dns_records_all(self, domain):
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'SPF']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return records

    def ip_geolocation(self, ip):
        try:
            response = self.session.get(
                f'http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,lat,lon,timezone,proxy,hosting')
            data = response.json()
            if data['status'] == 'success':
                return {
                    'ip': ip,
                    'country': data['country'],
                    'region': data['regionName'],
                    'city': data['city'],
                    'isp': data['isp'],
                    'org': data['org'],
                    'asn': data['as'],
                    'lat': data['lat'],
                    'lon': data['lon'],
                    'timezone': data['timezone'],
                    'proxy': data['proxy'],
                    'hosting': data['hosting']
                }
            else:
                return {'ip': ip, 'error': data.get('message')}
        except Exception as e:
            return {'ip': ip, 'error': str(e)}

    def shodan_scan(self, ip):
        api_key = self.api_keys.get('shodan')
        if not api_key:
            return {'error': 'Shodan API key required'}
        try:
            api = shodan.Shodan(api_key)
            result = api.host(ip)
            return {
                'ip': ip,
                'os': result.get('os'),
                'ports': result.get('ports'),
                'tags': result.get('tags'),
                'vulns': result.get('vulns'),
                'hostnames': result.get('hostnames'),
                'data': result.get('data', [])[:5]
            }
        except Exception as e:
            return {'error': str(e)}

    def ssl_certificate(self, host, port=443):
        try:
            cert = ssl.get_server_certificate((host, port))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            subject = dict(x509.get_subject().get_components())
            issuer = dict(x509.get_issuer().get_components())
            return {
                'host': host,
                'subject': {k.decode(): v.decode() for k, v in subject.items()},
                'issuer': {k.decode(): v.decode() for k, v in issuer.items()},
                'version': x509.get_version(),
                'serial': x509.get_serial_number(),
                'not_before': x509.get_notBefore().decode(),
                'not_after': x509.get_notAfter().decode(),
                'expired': x509.has_expired()
            }
        except Exception as e:
            return {'error': str(e)}

    def website_tech_stack_full(self, url):
        try:
            if not urlparse(url).scheme:
                url = 'https://' + url
            webpage = WebPage.new_from_url(url, timeout=15)
            tech = self.wappalyzer.analyze_with_versions_and_categories(webpage)
            response = self.session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            headers = dict(response.headers)
            return {
                'url': url,
                'status_code': response.status_code,
                'headers': {k: v for k, v in headers.items() if k.lower() not in ['set-cookie', 'cookie']},
                'title': soup.title.string.strip() if soup.title else None,
                'tech_stack': tech,
                'server': headers.get('Server'),
                'powered_by': headers.get('X-Powered-By')
            }
        except Exception as e:
            return {'error': str(e)}

    def email_harvester_recursive(self, url, max_depth=2):
        visited = set()
        emails = set()

        def crawl(current_url, depth):
            if depth > max_depth or current_url in visited:
                return
            visited.add(current_url)
            try:
                response = self.session.get(current_url, timeout=10)
                new_emails = self.find_emails_in_text(response.text)
                emails.update(new_emails)
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = urljoin(current_url, link['href'])
                    if urlparse(href).netloc == urlparse(url).netloc:
                        crawl(href, depth + 1)
            except:
                pass

        crawl(url if urlparse(url).scheme else 'https://' + url, 0)
        return list(emails)

    def find_emails_in_text(self, text):
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        return set(re.findall(pattern, text, flags=re.IGNORECASE))

    def breach_check_full(self, email):
        try:
            headers = {'hibp-api-key': self.api_keys.get('hibp'), 'User-Agent': 'OSINT-Framework'}
            response = self.session.get(
                f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}?includeUnverified=true', headers=headers)
            if response.status_code == 200:
                breaches = response.json()
                return [{'name': b['Name'], 'breach_date': b['BreachDate']} for b in breaches]
            elif response.status_code == 404:
                return []
            else:
                return {'error': response.text}
        except Exception as e:
            return {'error': str(e)}

    def port_scan(self, host, ports=None):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        open_ports = []

        def scan_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((host, port))
                return port if result == 0 else None
            finally:
                sock.close()

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_port, p): p for p in ports}
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    open_ports.append(r)
        return {'host': host, 'open_ports': sorted(open_ports)}

    def telegram_user(self, username):
        try:
            url = f'https://t.me/{username}'
            response = self.session.get(url, timeout=15)
            if response.status_code != 200:
                return {'error': 'User not found or blocked'}
            soup = BeautifulSoup(response.text, 'html.parser')
            data = {}
            title = soup.find('title')
            if title:
                data['title'] = title.get_text(strip=True)
            description = soup.find('meta', property='og:description')
            if description:
                data['bio'] = description['content']
            image = soup.find('meta', property='og:image')
            if image:
                data['profile_image'] = image['content']
            script = soup.find('script', type='application/ld+json')
            if script:
                try:
                    json_data = json.loads(script.string)
                    if isinstance(json_data, list):
                        json_data = json_data[0]
                    data.update({
                        'name': json_data.get('name'),
                        'type': json_data.get('@type'),
                        'member_count': json_data.get('member', {}).get('value')
                    })
                except:
                    pass
            if 'member_count' in data:
                data['type'] = 'channel' if 'channel' in response.text.lower() else 'group'
            else:
                data['type'] = 'user'
            data['username'] = username
            data['verified'] = 'verified' in response.text.lower()
            data['scam'] = 'scam' in response.text.lower()
            return data
        except Exception as e:
            return {'error': str(e)}

    def telegram_user_by_phone(self, phone):
        try:
            url = f'https://t.me/+{phone}'
            response = self.session.get(url, timeout=15, allow_redirects=True)
            if response.status_code == 200 and 'tgme_page' in response.text:
                final_url = response.url
                username = final_url.split('t.me/')[1].split('?')[0] if 't.me/' in final_url else None
                if username and username != f'+{phone}':
                    return self.telegram_user(username)
            return {'error': 'No public profile'}
        except Exception as e:
            return {'error': str(e)}

    def twitter_user(self, username):
        try:
            url = f'https://x.com/{username}'
            response = self.session.get(url, timeout=15)
            if response.status_code != 200:
                return {'error': 'User not found'}
            soup = BeautifulSoup(response.text, 'html.parser')
            data = re.search(r'window\.__INITIAL_STATE__ = ({.*?});', response.text)
            if not data:
                return {'error': 'No JSON data'}
            json_data = json.loads(data.group(1))
            user = json_data['entities']['users']['items'][0]
            return {
                'username': user['legacy']['screen_name'],
                'name': user['legacy']['name'],
                'bio': user['legacy']['description'],
                'location': user['legacy']['location'],
                'joined': user['legacy']['created_at'],
                'following': user['legacy']['friends_count'],
                'followers': user['legacy']['followers_count'],
                'tweets': user['legacy']['statuses_count'],
                'verified': user['legacy']['verified'],
                'profile_image': user['legacy']['profile_image_url_https'].replace('_normal', '')
            }
        except Exception as e:
            return {'error': str(e)}

    def instagram_user(self, username):
        try:
            url = f'https://www.instagram.com/{username}/?__a=1&__d=dis'
            response = self.session.get(url, timeout=15)
            if response.status_code != 200:
                return {'error': 'User not found'}
            data = response.json()
            user = data['graphql']['user']
            return {
                'username': user['username'],
                'full_name': user['full_name'],
                'bio': user['biography'],
                'posts': user['edge_owner_to_timeline_media']['count'],
                'followers': user['edge_followed_by']['count'],
                'following': user['edge_follow']['count'],
                'is_private': user['is_private'],
                'is_verified': user['is_verified'],
                'profile_pic': user['profile_pic_url_hd']
            }
        except Exception as e:
            return {'error': str(e)}

    def linkedin_profile(self, username):
        try:
            url = f'https://www.linkedin.com/in/{username}'
            response = self.session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            data = re.search(r'data":({.*})', response.text)
            if not data:
                return {'error': 'No data'}
            json_data = json.loads(data.group(1))
            profile = json_data['included'][0]
            return {
                'name': f"{profile.get('firstName', '')} {profile.get('lastName', '')}",
                'headline': profile.get('headline'),
                'location': profile.get('geoLocation', {}).get('geoLocationName'),
                'profile_url': url
            }
        except Exception as e:
            return {'error': str(e)}

    def github_user(self, username):
        try:
            url = f'https://api.github.com/users/{username}'
            response = self.session.get(url, headers={'Accept': 'application/vnd.github.v3+json'}, timeout=10)
            if response.status_code != 200:
                return {'error': 'User not found'}
            data = response.json()
            return {
                'username': data['login'],
                'name': data['name'],
                'bio': data['bio'],
                'company': data['company'],
                'location': data['location'],
                'public_repos': data['public_repos'],
                'followers': data['followers'],
                'profile_url': data['html_url']
            }
        except Exception as e:
            return {'error': str(e)}

    def username_search_all(self, username):
        platforms = [
            ('Telegram', self.telegram_user),
            ('Twitter', self.twitter_user),
            ('Instagram', self.instagram_user),
            ('LinkedIn', self.linkedin_profile),
            ('GitHub', self.github_user)
        ]
        results = {}

        def check_platform(name, func):
            try:
                result = func(username)
                if 'error' not in result:
                    results[name] = result
            except:
                pass

        with ThreadPoolExecutor(max_workers=8) as executor:
            for name, func in platforms:
                executor.submit(check_platform, name, func)
        return results

    def social_media_scan(self, target):
        results = {}
        if re.match(r'^\+?\d{10,15}$', target):
            results['telegram_phone'] = self.telegram_user_by_phone(target)
        elif '@' in target:
            username = target.split('@')[0]
            results['username_from_email'] = self.username_search_all(username)
        else:
            results['username_search'] = self.username_search_all(target)
        return results

    def run_full_scan(self, target):
        results = {}
        if self.is_domain(target):
            results['whois'] = self.domain_whois(target)
            results['dns'] = self.dns_records_all(target)
            results['subdomains'] = self.subdomain_enum_crtsh(target)
            results['techstack'] = self.website_tech_stack_full(f"https://{target}")
            results['ssl'] = self.ssl_certificate(target)
            results['emails'] = self.email_harvester_recursive(f"https://{target}", max_depth=1)
            results['social'] = self.social_media_scan(target)
        elif self.is_ip(target):
            results['geolocation'] = self.ip_geolocation(target)
            results['ports'] = self.port_scan(target)
            if 'shodan' in self.api_keys:
                results['shodan'] = self.shodan_scan(target)
        return results

    def is_domain(self, target):
        return re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', target) is not None

    def is_ip(self, target):
        parts = target.split('.')
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def run_scan(self, target, scan_type):
        if scan_type == 'full':
            return self.run_full_scan(target)
        elif scan_type == 'social_full':
            return self.social_media_scan(target)
        elif scan_type.startswith('social_'):
            method_name = scan_type.replace('social_', '')
            method = getattr(self, method_name, None)
            if method and callable(method):
                return method(target)
        else:
            method = getattr(self, scan_type, None)
            if method and callable(method):
                return method(target)
        return {'error': 'Invalid scan type'}


def main():
    if len(sys.argv) < 3:
        print(json.dumps({'error': 'Usage: python osintpy.py <target> <scan_type>'}))
        sys.exit(1)

    target = sys.argv[1]
    scan_type = sys.argv[2]

    api_keys = {
        'shodan': None,
        'hibp': None
    }

    framework = OSINTPY(api_keys)
    result = framework.run_scan(target, scan_type)

    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()
