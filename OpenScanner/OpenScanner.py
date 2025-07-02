import requests
import socket
from datetime import datetime
import whois
import json
import re
import argparse
import ipaddress
import dns.resolver
from urllib.parse import quote_plus

# Replace with your actual API keys or leave as None
ABUSEIPDB_API_KEY = None  # https://www.abuseipdb.com/register
VT_API_KEY = None         # https://www.virustotal.com/gui/join-us
URLSCAN_API_KEY = None    # https://urlscan.io/user/signup
SHODAN_API_KEY = None     # https://account.shodan.io/register
GREYNOISE_API_KEY = None  # https://viz.greynoise.io/signup
CENSYS_API_ID = None      # https://accounts.censys.io/register
CENSYS_API_SECRET = None  # https://accounts.censys.io/register
SECURITYTRAILS_API_KEY = None 
ABUSECH_AUTH_KEY= None    #https://auth.abuse.ch/


# ==== Tools ====
def is_ip(target):
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target))

def is_domain(target):
    return bool(re.match(r"^(https?://)?(?!\-)([a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$", target))

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_dns_records(domain):
    for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            print(f"{record_type} records:")
            for rdata in answers:
                print(f" - {rdata.to_text()}")
        except Exception:
            pass

def check_abuseipdb(ip, verbose=False):
    if not ABUSEIPDB_API_KEY:
        print(f"[AbuseIPDB] API key not set. Check manually: https://www.abuseipdb.com/check/{ip}")
        return
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        response = requests.get(url, headers=headers, params=params)
        data = response.json()["data"]

        if verbose:
            print(json.dumps(data, indent=2))
        else:
            print(f"- Reports: {data.get('totalReports')}")
            print(f"- Abuse Confidence Score: {data.get('abuseConfidenceScore')}%")
            print(f"- ISP: {data.get('isp', 'N/A')}")
            print(f"- Usage Type: {data.get('usageType', 'N/A')}")
            print(f"- ASN: {data.get('asn', 'N/A')}")
            print(f"- Domain Name: {data.get('domain', 'N/A')}")
            print(f"- Country: {data.get('countryName', 'N/A')}")
            print(f"- Link: https://www.abuseipdb.com/check/{ip}")

    except Exception as e:
        print(f"[AbuseIPDB] Error: {e}")

def check_greynoise(ip, verbose=False):
    if not GREYNOISE_API_KEY:
        print(f"[GreyNoise] API key not set. Check manually: https://www.greynoise.io/viz/ip/{ip}")
        return
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {
            "key": GREYNOISE_API_KEY,
            "Accept": "application/json"
        }
        response = requests.get(url, headers=headers)
        data = response.json()

        if verbose:
            print(json.dumps(data, indent=2))
        else:
            tags = data.get('tags', [])
            print(f"- Name: {data.get('name', 'N/A')}")
            print(f"- Classification: {data.get('classification', 'N/A')}")
            print(f"- Tags: {', '.join(tags) or 'None'}")
            vpn_related = [t for t in tags if any(x in t.lower() for x in ['vpn', 'proxy', 'tor', 'hosting'])]
            if vpn_related:
                print(f"⚠️ Possible VPN/Proxy Detected")
            print(f"- Link: https://viz.greynoise.io/ip/{ip}")
    except Exception as e:
        print(f"[GreyNoise] Error: {e}")

def check_ipinfo(ip, verbose=False):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)
        data = response.json()

        if verbose:
            print(json.dumps(data, indent=2))
        else:
            print(f"- City: {data.get('city', 'N/A')}")
            print(f"- Org: {data.get('org', 'N/A')}")
            print(f"- ASN: {data.get('asn', {}).get('asn', 'N/A')}")
            print(f"- Link: https://ipinfo.io/{ip}")
    except Exception as e:
        print(f"[ipinfo.io] Error: {e}")

def check_virustotal(query, verbose=False):
    if not VT_API_KEY:
        print(f"[VirusTotal] API key not set. Check manually: https://www.virustotal.com/gui/search/{quote_plus(query)}")
        return
    try:
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/search?query={quote_plus(query)}"
        response = requests.get(url, headers=headers)
        data = response.json()

        if verbose:
            print(json.dumps(data, indent=2))
        else:
            try:
                stats = data["data"][0]["attributes"]["last_analysis_stats"]
                harmless = stats.get("harmless", 0)
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                print(f"- Harmless: {harmless}")
                print(f"- Malicious: {malicious}")
                print(f"- Suspicious: {suspicious}")
            except:
                print("- No analysis data found.")
            print(f"- Link: https://www.virustotal.com/gui/search/{quote_plus(query)}")
    except Exception as e:
        print(f"[VirusTotal] Error: {e}")

def check_urlscan(query, verbose=False):
    if not URLSCAN_API_KEY:
        print(f"[urlscan.io] API key not set. Search manually: https://urlscan.io/search/#domain:{quote_plus(query)}")
        print(f"- Submit a new scan manually: https://urlscan.io/")
        return
    try:
        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }
        # Use search API to find existing scans
        url = f"https://urlscan.io/api/v1/search/?q=domain:{quote_plus(query)}"
        response = requests.get(url, headers=headers, timeout=10)
        results = response.json()

        if verbose:
            print(json.dumps(results, indent=2))
        else:
            total = results.get("total", 0)
            print(f"- Found {total} scan(s) for domain: {query}")
            for result in results.get("results", [])[:5]:
                print(f"  - URL: {result.get('page', {}).get('url', 'N/A')}")
                print(f"    Scan Date: {result.get('task', {}).get('time', 'N/A')}")
                print(f"    Link: {result.get('result', 'N/A')}")
            print(f"- Submit new scan: https://urlscan.io/#submit-form={quote_plus(query)}")
    except Exception as e:
        print(f"[urlscan.io] Error: {e}")


def get_whois(domain, verbose=False):
    try:
        w = whois.whois(domain)

        def fmt(dt):
            if isinstance(dt, list):
                dt = dt[0]
            if isinstance(dt, datetime):
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            return str(dt)

        if not w.domain_name:
            print(f"[WHOIS] No WHOIS data found for: {domain}")
            return

        if verbose:
            print(json.dumps(w, indent=2, default=str))
        else:
            print(f"- Domain: {w.domain_name}")
            print(f"- Registrar: {w.registrar or 'N/A'}")
            print(f"- Creation Date: {fmt(w.creation_date)}")
            if w.creation_date and (datetime.now() - w.creation_date).days < 60:
                print("⚠️ Domain is newly registered!")
            print(f"- Expiry Date: {fmt(w.expiration_date)}")
            print(f"- Name Servers: {', '.join(w.name_servers) if w.name_servers else 'N/A'}")
            print(f"- WHOIS Link: https://who.is/whois/{domain}")
    except Exception as e:
        if "No match for" in str(e):
            print(f"[WHOIS] No match found for domain: {domain}")
        else:
            print(f"[WHOIS] Error: {e}")


def check_crtsh(domain, verbose=False):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url)
        data = r.json()
        if verbose:
            print(json.dumps(data, indent=2))
        else:
            print(f"- Found {len(data)} certificates")
            print(f"- Link: https://crt.sh/?q=%25.{domain}")
    except Exception as e:
        print(f"[crt.sh] Error: {e}")

def check_shodan(ip, verbose=False):
    if not SHODAN_API_KEY:
        print(f"[Shodan] API key not set. Check manually: https://www.shodan.io/host/{ip}")
        return
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        data = response.json()
        if verbose:
            print(json.dumps(data, indent=2))
        else:
            print(f"- Org: {data.get('org', 'N/A')}")
            print(f"- OS: {data.get('os', 'N/A')}")
            print(f"- Open Ports: {data.get('ports', [])}")
            print(f"- Link: https://www.shodan.io/host/{ip}")
    except Exception as e:
        print(f"[Shodan] Error: {e}")

def check_expandurl(url, verbose=False):
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        final_url = response.url
        print(f"- Expanded URL: {final_url}")
    except Exception as e:
        print(f"[ExpandURL] Error expanding {url}: {e}")

def check_censys(ip, verbose=False):
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        print(f"[Censys] API credentials not set. Check manually: https://search.censys.io/hosts/{ip}")
        return
    try:
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        response = requests.get(url, auth=(CENSYS_API_ID, CENSYS_API_SECRET))
        data = response.json()
        if verbose:
            print(json.dumps(data, indent=2))
        else:
            hit = data.get("result", {})
            services = hit.get("services", [])
            print(f"- Found {len(services)} services")
            print(f"- Link: https://search.censys.io/hosts/{ip}")
    except Exception as e:
        print(f"[Censys] Error: {e}")

def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        print(f"[Resolve] Error: {e}")
        return None
    
def check_browserling(url, verbose=False):
    print(f"- Open in Browserling: https://www.browserling.com/browse/win/7/https://{url.lstrip('https://').lstrip('http://')}")

def safe_expandurl(url, verbose=False):
    print(f"- Manual expand: https://expandurl.com/?url={quote_plus(url)}")

def check_ipvoid(ip, verbose=False): # This really isn't kosher and will probably get you rate limited, be warned 
    try:
        r = requests.post(
            "https://www.ipvoid.com/ip-blacklist-check/",
            headers={"User-Agent": "Mozilla/5.0"},
            data={"ipaddr": ip},
            timeout=10
        )
        if r.status_code != 200:
            print(f"→ Failed to fetch IPVoid result (HTTP {r.status_code})")
            return

        m = re.search(r"Detections Count.*?<span class=\"label.*?\">(\d+/\d+)</span>", r.text, re.DOTALL)
        print(f"- Detections Count: {m.group(1)}" if m else "- Detection count not found.")

        if verbose:
            blacklists = re.findall(
                r'<tr><td><i class="fa fa-exclamation-circle text-danger".*?>(.*?)</td><td>', r.text)
            if blacklists:
                print(f"- Listed on {len(blacklists)} site(s):")
                for site in blacklists:
                    print(f"  • {site.strip()}")
            else:
                print("- Not listed on any blacklists.")

        print(f"- Link: https://www.ipvoid.com/ip-blacklist-check/?ip={ip}")

    except Exception as e:
        print(f"[IPVoid] Error: {e}")


def check_securitytrails(domain, verbose=False):
    if not SECURITYTRAILS_API_KEY:
        print(f"[SecurityTrails] API key not set. Check manually: https://securitytrails.com/domain/{domain}")
        return
    try:
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        
        # WHOIS lookup
        whois_url = f"https://api.securitytrails.com/v1/domain/{domain}/whois"
        whois_resp = requests.get(whois_url, headers=headers)
        whois_data = whois_resp.json()

        # Subdomains lookup
        sub_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        sub_resp = requests.get(sub_url, headers=headers)
        sub_data = sub_resp.json()

        if verbose:
            print(json.dumps({"whois": whois_data, "subdomains": sub_data}, indent=2))
        else:
            print(f"- Registrar: {whois_data.get('registrar', 'N/A')}")
            print(f"- Created: {whois_data.get('created', 'N/A')}")
            print(f"- Updated: {whois_data.get('updated', 'N/A')}")
            print(f"- Subdomains: {', '.join(sub_data.get('subdomains', [])[:5]) or 'None'}")
            print(f"- Link: https://securitytrails.com/domain/{domain}")
    except Exception as e:
        print(f"[SecurityTrails] Error: {e}")

def query_urlhaus(target, verbose=False):
    if not ABUSECH_AUTH_KEY:
        print(f"[URLHaus] API key not set. Check manually: https://urlhaus.abuse.ch/host/{target}")
        return
    try:
        data = {"host": target}
        headers = {
            "Auth-Key": ABUSECH_AUTH_KEY
        }
        response = requests.post('https://urlhaus-api.abuse.ch/v1/host/', data=data, headers=headers, timeout=10)
        json_response = response.json()

        if json_response.get('query_status') == 'ok':
            urls = json_response.get("urls", [])
            if verbose:
                print(json.dumps(json_response, indent=4, sort_keys=False))
            else:
                print(f"- Found {len(urls)} URL(s) associated with host: {target}")
                for entry in urls[:5]:  # show top 5 entries
                    print(f"  - URL: {entry.get('url')}")
                    print(f"    Threat: {entry.get('threat', 'N/A')}")
                    print(f"    Status: {entry.get('url_status', 'N/A')}")
                    print(f"    Date Added: {entry.get('date_added', 'N/A')}")
                print(f"- Full results: https://urlhaus.abuse.ch/host/{target}/")
        elif json_response.get('query_status') == 'no_results':
            print(f"- No results for: {target}")
        else:
            print(f"[URLHaus] Unexpected response: {json_response.get('query_status')}")
    except Exception as e:
        print(f"[URLHaus] Error: {e}")


# ==== Main ====

def main():
    parser = argparse.ArgumentParser(description="OSINT Scanner for Domains/IPs")
    parser.add_argument("target", help="Domain or IP address to investigate")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose JSON output")
    parser.add_argument("--expand", "-e", action="store_true", help="Enable active URL expansion, warning this will send a Python web request to a website to check for redirects. Only enable this if running in a sandboxed environment.")

    print("start")

    args = parser.parse_args()

    target = args.target
    verbose = args.verbose
    
    # Determine if it's a domain or IP

    if is_ip(target):
        ip = target
        is_domain_target = False
    elif is_domain(target):
        ip = resolve_domain_to_ip(target)
        is_domain_target = True
    else:
        print("❌ Target is neither a valid IP nor domain. Exiting.")
        return

    if not ip:
        print("❌ Could not resolve IP. Exiting.")
        return

    if is_private_ip(ip):
        print(f"⚠️ {ip} is a private/reserved IP address. Exiting.")
        return

    print(f"\n🔍 Investigating: {target}")
    print(f"Resolved IP: {ip}\n")

    # ========== IP Section ==========
    print("=== IP Analysis ===")
    print("[AbuseIPDB]")
    check_abuseipdb(ip, verbose)

    print("\n[GreyNoise]")
    check_greynoise(ip, verbose)

    print("\n[ipinfo.io]")
    check_ipinfo(ip, verbose)

    print("\n[Shodan]")
    check_shodan(ip, verbose)

    print("\n[Censys]")
    check_censys(ip, verbose)

    print("\n[IPVoid]")
    check_ipvoid(ip, verbose)

    # ========== Domain Section ==========
    if is_domain_target:
        print("\n=== Domain Analysis ===")
        
        print("[VirusTotal]")
        check_virustotal(target, verbose)

        print("\n[WHOIS]")
        get_whois(target, verbose)

        print("\n[crt.sh]")
        check_crtsh(target, verbose)

        print("\n[Hunting.abuse.ch]")
        query_urlhaus(target, verbose)

        print("\n[SecurityTrails]")
        check_securitytrails(target, verbose)

        print("\n[URLScan.io]")
        check_urlscan(target, verbose)

        print("\n[DNS Records]")
        get_dns_records(target)

        print("\n[Browserling]")
        check_browserling(target, verbose)

        if target.startswith("http://") or target.startswith("https://"):
            print("\n[ExpandURL]")
            if args.expand:
                check_expandurl(target, verbose)
            else:
                safe_expandurl(target, verbose)

if __name__ == "__main__":
    main()