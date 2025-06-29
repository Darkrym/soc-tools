---
author:
  name: Darkrym
date: 2025-06-27
linktitle: IP & Domain Cheat Sheet
type:
  - post
  - posts
title: IP & Domain Investigation Cheat Sheet
weight: 20
series:
  - cheat_sheets
---
This IP and domain investigation reference sheet outlines essential techniques and tools for assessing suspicious infrastructure in cybersecurity contexts. It supports triage, reputation analysis, WHOIS lookups, DNS inspection, passive intelligence, and safe payload retrieval. Tailored for analysts, incident responders, threat hunters, and DFIR professionals, it streamlines workflows for identifying malicious indicators, uncovering historical associations, and making informed decisions during investigations.

---

##  Immediate Questions to Ask

- Is this a public IP or private/reserved?
- Is the domain newly registered, sinkholed, or typosquatted?
- Is the IP on threat feeds or blacklists?
- Does it belong to a known cloud/VPN/proxy provider?
- What are the historical DNS resolutions and WHOIS?

---

##  Tools for IP & Domain Analysis

| Tool                                              | Use Case                                                                                       |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [**AbuseIPDB**](https://www.abuseipdb.com/)       | Check if IP is reported for malicious activity                                                 |
| [**VirusTotal**](https://www.virustotal.com/)     | IP/domain reputation, passive DNS, related IOCs                                                |
| [**URLScan.io**](https://urlscan.io/)             | Scan web pages, extract scripts, HTML, and redirect chains                                     |
| [**Shodan**](https://www.shodan.io/)              | Open ports, services, banners on public IPs                                                    |
| [**Censys**](https://search.censys.io/)           | Asset discovery, certificates, services, open ports                                            |
| [**GreyNoise**](https://viz.greynoise.io/)        | Identify noisy scanners vs targeted threats                                                    |
| [**Browserling**](https://www.browserling.com/)   | Safe website browsing and JS/redirect testing                                                  |
| [**Spur.us**](https://app.spur.us/search?q=)      | Identify proxies, VPNs, hosting info                                                           |
| [**SecurityTrails**](https://securitytrails.com/) | Historical DNS, WHOIS, subdomains                                                              |
| [**Hunting.abuse.ch**](https://hunting.abuse.ch/) | IOC feeds (URLhaus, MalwareBazaar)                                                             |
| [**ExpandURL**](http://expandurl.net/)            | Reveal full destination of shortened/tracked URLs                                              |
| [**IPVoid**](https://www.ipvoid.com/)             | Quick IP/domain blacklist check, ASN info                                                      |
| [**WHOIS**](https://www.whois.com/whois/)         | Ownership and registration information                                                         |
| [**RiskIQ**](https://community.riskiq.com/home)   | Passive DNS, WHOIS history, SSL certs (now merged into Microsoft Defender Threat Intelligence) |

---

## IP Classes and Ranges

| Class | Range                         | Type      | CIDR Notation                   | Notes                     |
| ----- | ----------------------------- | --------- | ------------------------------- | ------------------------- |
| A     | 1.0.0.0 – 9.255.255.255       | Public    | 1.0.0.0/8 – 9.0.0.0/8           | Public routable           |
| A (P) | 10.0.0.0 – 10.255.255.255     | Private   | 10.0.0.0/8                      | Private use               |
| A     | 11.0.0.0 – 126.255.255.255    | Public    | 11.0.0.0/8 – 126.0.0.0/8        | Public routable           |
| A     | 127.0.0.0 – 127.255.255.255   | Special   | 127.0.0.0/8                     | Loopback addresses        |
| B     | 128.0.0.0 – 191.255.255.255   | Mixed     | 128.0.0.0/16 – 191.255.0.0/16   | Public and private ranges |
| B (P) | 172.16.0.0 – 172.31.255.255   | Private   | 172.16.0.0/12                   | Private use               |
| C     | 192.0.0.0 – 223.255.255.255   | Mixed     | 192.0.0.0/24 – 223.255.255.0/24 | Public and private        |
| C (P) | 192.168.0.0 – 192.168.255.255 | Private   | 192.168.0.0/16                  | Private use               |
| D     | 224.0.0.0 – 239.255.255.255   | Multicast | 224.0.0.0/4                     | Not for general use       |
| E     | 240.0.0.0 – 255.255.255.255   | Reserved  | 240.0.0.0/4                     | Research/experimental use |

---

## CLI Commands

### WHOIS + DNS
```bash
# WHOIS lookup
whois example.com

# DNS records (A, MX, TXT, CNAME)
dig example.com ANY +short
dig +trace example.com

# Use alternative DNS resolver (Useful for internal DNS Servers)
nslookup example.com 8.8.8.8
```

### IP Geolocation + ASN
```bash
curl ipinfo.io/8.8.8.8
curl https://ipapi.co/8.8.8.8/json/
```

### Historical WHOIS and Certificates
```bash
curl "https://crt.sh/?q=%.example.com&output=json"
```

---
## Curl Usage

> ⚠️ **Always perform payload retrieval in an VM with VPN enabled.**

```bash
# Download raw payload
curl http://example.com/payload

# View HTTP headers
curl -I https://example.com

# Follow redirects and trace
curl -v -L https://short.url

# Fetch page and convert to plaintext
curl -s https://example.com | html2text

# Custom headers - Some threat actors will perform "authentication" on their servers by using custom headers.
curl https://example.com -A "CustomUserAgent"
curl https://example.com -H "Header: value"
curl https://example.com -b "cookie=value"
curl https://example.com --referer "https://source.com"
```

---
## Suggested Workflow

### Step 1: Initial Triage – Begin with URLScan.io or AbuseIPDB
- **For URLs**: Use [URLScan.io](https://urlscan.io)
  - Review the screenshot and network tab
  - Note any resource files and redirects
  - Check for unusual behaviour (e.g. strange hosting, suspicious scripts)

- **For IPs**: Use [AbuseIPDB](https://abuseipdb.com)
  - Check report history
  - Look for associated abuse categories (e.g. brute force, phishing)

---

### Step 2: IP & Domain Reputation Checks
Query the IP or domain in:
- [Spur.us](https://spur.us)
- [IPVoid](https://www.ipvoid.com)
- [GreyNoise](https://viz.greynoise.io)
- [**Hunting.abuse.ch**](https://hunting.abuse.ch)

Look for:
- Known blacklists
- Cloud hosting services (e.g. AWS, Azure, GCP)
- Scanning or malicious behaviour reports

---

### Step 3: WHOIS Lookup
Use tools like 
- `whois`
- [DomainTools](https://whois.domaintools.com)
- [SecurityTrails](https://securitytrails.com)

Look for:
- Domain creation/expiry dates
- Registrar details
- Registrant email (useful for pivoting to other domains)

---

### Step 4: Certificate & Passive DNS Analysis
Query:
- [Censys](https://censys.io)
- [crt.sh](https://crt.sh)
- [SecurityTrails](https://securitytrails.com)

Look for:
- SSL certificate reuse across domains
- Historical IP/domain associations
- Subdomain enumeration

---

### Step 5: VirusTotal Search
Use [VirusTotal](https://www.virustotal.com) to search for domain or IP.

Check for:
- Detection engine results
- Behavioural graph and activity
- Related malicious files or domains

---

### Step 6: Retrieve Payloads
Use:
- [Browserling](https://www.browserling.com)
- `curl` (in a VM with VPN)
- A browser (in a VM with VPN)

Purpose:
- Safely interact with and collect potential payloads
- Observe dynamic behaviour without exposing your host system

---

## Behavioural Indicators

| Type   | Suspicious Traits                                                        |
| ------ | ------------------------------------------------------------------------ |
| Domain | New registration, strange TLDs, WHOIS privacy, typosquatting, homoglyphs |
| IP     | Blacklisted, TOR exit node, cloud host, reverse DNS mismatch             |
| URL    | Shortened, base64-encoded params, IP-based URLs, excessive redirects     |
| DNS    | Fast-flux, wildcard abuse, TXT query abuse, NXDOMAIN spikes              |

---

> ✉️ *For any domains/URLs shared with colleagues, consider defanging (e.g., `hxxp://malicious[.]site`) to prevent accidental clicks.*