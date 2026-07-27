# K1NZR3C0N — Red Team Arsenal

Tài liệu tham chiếu kỹ thuật cho từng giai đoạn tấn công.  
Tổ chức theo kill chain: **Recon → Enumerate → Expand Surface → Exploit**.

---

## Phase 1 — Subdomain & Asset Reconnaissance

### 1.1 Passive Intelligence Sources

Ưu tiên passive trước để tránh noise trong logs target. Kết hợp nhiều nguồn vì không nguồn nào có 100% coverage.

#### Internet Scanners (Shodan-class)

| Source | URL | Notes |
|--------|-----|-------|
| Shodan | [shodan.io](https://shodan.io) | Port/banner + SSL cert history |
| Censys | [censys.com](https://censys.com/) | Certificate + host data, tốt hơn Shodan cho cert |
| FOFA | [en.fofa.info](https://en.fofa.info/) | Tốt với target Châu Á |
| ZoomEye | [zoomeye.hk](https://www.zoomeye.hk/) | Kết hợp với FOFA |
| Quake | [quake.360.cn](https://quake.360.cn/) | 360.cn — coverage riêng |
| BinaryEdge | [binaryedge.io](https://binaryedge.io) | Real-time scan data |
| Netlas | [netlas.io](https://netlas.io/) | Mạnh về DNS + cert |
| HunterMap | [hunter.how](https://hunter.how/) | |
| FullHunt | [fullhunt.io](https://fullhunt.io/) | Attack surface management |
| Odin | [odin.io](https://odin.io/) | |
| LeakIX | [leakix.net](https://leakix.net/) | Exposed services + leaks |

#### Certificate Transparency

Khai thác CT logs để tìm subdomain chưa public. Hiệu quả cao với wildcard certs.

| Source | URL | Notes |
|--------|-----|-------|
| crt.sh | [crt.sh](https://crt.sh) | Free, realtime CT logs |
| CertSpotter | [sslmate.com/certspotter](https://sslmate.com/certspotter/) | Monitor + history |
| MerkleMap | [merklemap.com](https://www.merklemap.com) | |
| MySSL | [myssl.com](https://myssl.com) | |

#### DNS / Archive / Crawl History

| Source | URL | Notes |
|--------|-----|-------|
| DNSDumpster | [dnsdumpster.com](https://dnsdumpster.com/) | Free, DNS + MX + TXT |
| RapidDNS | [rapiddns.io](https://rapiddns.io/) | |
| DNSRepo | [dnsarchive.net](https://dnsarchive.net/) | DNS history |
| WaybackArchive | [archive.org/wayback](https://archive.org/wayback) | URLs từ archived pages |
| CommonCrawl | [index.commoncrawl.org](https://index.commoncrawl.org/) | Petabyte-scale crawl |
| URLScan | [urlscan.io](https://urlscan.io/) | Browser-based scan history |
| BufferOver | [tls.bufferover.run](https://tls.bufferover.run/) | |
| HackerTarget | [hackertarget.com](https://hackertarget.com/) | |

#### Threat Intelligence

| Source | URL | Notes |
|--------|-----|-------|
| VirusTotal | [virustotal.com](https://virustotal.com/) | Relations graph cực mạnh |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com/) | Passive DNS |
| ThreatCrowd | [ci-www.threatcrowd.org](http://ci-www.threatcrowd.org/) | |
| AbuseIPDB | [abuseipdb.com](https://abuseipdb.com) | IP reputation + history |
| IntelX | [intelx.io](https://intelx.io/) | Data leaks + darkweb |
| HudsonRock | [cavalier.hudsonrock.com](https://cavalier.hudsonrock.com) | Infostealer credential data |

#### Commercial / API Keys Required

| Source | URL | Notes |
|--------|-----|-------|
| Chaos (PD) | [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io/) | Subfinder sử dụng, cần key |
| SecurityTrails | [securitytrails.com](http://securitytrails.com/) | DNS history + WHOIS history |
| BeVigil | [bevigil.com](https://bevigil.com/login) | Subdomain từ mobile apps |
| Trickest | [trickest.io](https://trickest.io/) | |
| C99 | [subdomainfinder.c99.nl](https://subdomainfinder.c99.nl/) | |
| RedHuntLabs | [devportal.redhuntlabs.com](https://devportal.redhuntlabs.com/) | |
| ShrewdEye | [shrewdeye.app](https://shrewdeye.app/api) | |
| Digitorus | [digitorus.com](https://www.digitorus.com/) | |
| ARP Syndicate | [arpsyndicate.io](https://www.arpsyndicate.io/pricing.html) | |
| DigitalYama | [digitalyama.com](https://digitalyama.com/) | |
| Cyfare | [cyfare.net](https://cyfare.net) | |
| WhoisXML | [whoisxmlapi.com](https://whoisxmlapi.com) | WHOIS + DNS |
| Anubis | [jldc.me/anubis](https://jldc.me/anubis) | |
| Racent | [face.racent.com](https://face.racent.com) | |
| SiteDossier | [sitedossier.com](https://sitedossier.com/) | |
| RSECloud | [rsecloud.com/search](https://rsecloud.com/search) | |
| BuiltWith | [api.builtwith.com](https://api.builtwith.com/domain-api) | Tech stack fingerprint |
| CodeRog | [rapidapi.com/coderog](https://rapidapi.com/coderog-coderog-default/api/subdomain-finder5/pricing) | |
| Google (CSE) | [programmablesearchengine.google.com](https://programmablesearchengine.google.com/controlpanel/create) | Google dorking |
| Facebook | [developers.facebook.com](https://developers.facebook.com/) | Certificate transparency |
| RapidAPI | [rapidapi.com/hub](https://rapidapi.com/hub) | Aggregator nhiều nguồn |

---

### 1.2 Active Enumeration Tools

Dùng sau passive. Tạo DNS traffic trực tiếp đến resolver — có thể bị phát hiện.

| Tool | Trong workflow | Command mẫu |
|------|---------------|-------------|
| **subfinder** | `subfinder` step | `subfinder -d target.com -all -recursive -o out.txt` |
| **assetfinder** | `assetfinder` step | `assetfinder --subs-only target.com` |
| **findomain** | `findomain` step | `findomain -t target.com -u out.txt` |
| **amass** | (optional) | `amass enum -passive -d target.com` |
| **sublist3r** | `sublist3r` step | `sublist3r -d target.com -o out.txt` |
| **OneForAll** | `oneforall` step | Tổng hợp ~60 nguồn |
| **Chaos** | `chaos` step | Tập hợp bug bounty scope |
| **gobuster** (dns) | `gobuster_dns` step | `gobuster dns -d target.com -w subdomains-top1m.txt -t 50` |

### 1.3 Resolution & Validation

```bash
# Resolve và lọc live subdomain
dnsx -l subdomains.txt -a -aaaa -cname -o resolved.txt -json

# Check subdomain takeover
subzy run --targets subdomains.txt --concurrency 100 --hide-fails
```

---

## Phase 2 — Service Enumeration

### 2.1 Port Scanning Strategy

```
Fast sweep (naabu) → Targeted deep scan (rustscan/nmap)
```

| Tool | Use case | Command |
|------|----------|---------|
| **naabu** | Fast TCP sweep all ports | `naabu -l hosts.txt -p - -rate 1000 -json -o ports.jsonl` |
| **rustscan** | Fastest open port finder | `rustscan -a host --range 1-65535 --batch-size {batch}` |
| **nmap** (TCP) | Service version + scripts | `nmap -sV -sC -T4 -p {ports} host` |
| **nmap** (UDP) | Critical UDP services | `nmap -sU --top-ports 200 host` |

### 2.2 Web Service Fingerprinting

```bash
# httpx — HTTP probing + fingerprint
httpx -l hosts.txt -status-code -title -tech-detect -td \
  -content-length -json -o httpx.jsonl

# Quan trọng: -td (tech detect) giúp prioritize target
# Node.js app → check prototype pollution
# PHP → check file inclusion
# Java → check deserialization
```

---

## Phase 3 — Web Attack Surface Expansion

### 3.1 URL & Path Discovery (Crawling)

```bash
# katana — JS-aware crawler
katana -u https://target.com -depth 5 -jc -kf all \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg \
  -o katana.jsonl -json

# gau — Passive URL from archives
gau --blacklist png,jpg,gif,css,woff,svg target.com \
  --json -o gau.jsonl

# waybackurls — Wayback Machine
echo target.com | waybackurls
```

### 3.2 Directory & File Bruteforce

| Tool | Mạnh ở | Command mẫu |
|------|--------|-------------|
| **ffuf** | Fast, flexible filter | `ffuf -u URL/FUZZ -w wordlist.txt -mc 200,301,302,403 -fs 0` |
| **feroxbuster** | Recursive, Rust | `feroxbuster -u URL -w wordlist.txt --depth 3 -x php,asp,aspx` |
| **gobuster** (dir) | Stable, simple | `gobuster dir -u URL -w wordlist.txt -x php,html,js` |
| **dirsearch** | Python, nhiều extensions | `dirsearch -u URL -e php,asp,aspx,js -x 404,403` |

### 3.3 Hidden Parameter Discovery

**Mục tiêu**: Tìm parameter ẩn không documented — IDOR, mass assignment, debug flags, bypass.

#### Tools

| Tool | Phương pháp | Tốc độ | Ghi chú |
|------|------------|--------|---------|
| **Arjun** | GET/POST/JSON/XML bruteforce | Trung bình | Multi-thread, stable |
| **x8** | Smart diff-based detection | Nhanh (Rust) | Ít false positive hơn |
| **fallparams** | Wordlist-based, Go | Nhanh | |
| **Param-miner** | Burp Suite extension | — | Tốt nhất cho manual testing |
| **kiterunner** | API route + param discovery | Nhanh | Dùng Assetnote wordlists |

#### Commands

```bash
# Arjun — GET + POST, detect hidden params
arjun -u https://target.com/api/endpoint \
  -w /path/to/large.txt \
  --stable --rate-limit 10

# x8 — Smart detection, ít noise hơn
x8 -u "https://target.com/api/?FUZZ" \
  -w params.txt \
  -X GET --output-format json

# kiterunner — API routes từ Assetnote wordlists
kr scan https://target.com -w routes-large.kite \
  --fail-status-codes 400,401,404,403,501,502,426,411

# fallparams
fallparams -u https://target.com -w params.txt
```

#### Wordlists (Priority Order)

```
# Param bruteforce — từ nhỏ đến lớn
1. arjun/small.txt     (~500)   — quick check
2. arjun/medium.txt    (~5k)    — standard
3. arjun/large.txt     (~25k)   — thorough
4. samlists/sam-cc-parameters-lowercase-all.txt — real-world corpus
5. samlists/sam-cc-parameters-mixedcase-all.txt — case variations

# API routes — Assetnote
https://wordlists-cdn.assetnote.io/data/
→ httparchive_apiroutes_YYYYMMDD.txt  (API routes từ HTTPArchive)
→ routes-large.kite                   (kiterunner format)
```

**Khi nào cần param discovery:**
- Sau khi có live HTTP endpoints từ httpx
- Focus vào API endpoints (`/api/`, `/v1/`, `/graphql`)
- Endpoints trả về 200 với empty body — thường có hidden behavior
- Admin panels

### 3.4 Virtual Host Fuzzing

```bash
# gobuster vhost
gobuster vhost -u https://target.com \
  -w vhosts-wordlist.txt --append-domain

# ffuf vhost
ffuf -w vhosts-wordlist.txt \
  -u https://target.com \
  -H "Host: FUZZ.target.com" \
  -fs {baseline_size}
```

---

## Phase 4 — Vulnerability Assessment

### 4.1 Template-Based Scanning (Fast, Automated)

#### Nuclei

```bash
# Standard — community templates
nuclei -l live_hosts.txt \
  -t /root/nuclei-templates \
  -severity critical,high,medium \
  -json -o nuclei.jsonl \
  -rate-limit 150 -bulk-size 25

# Với community templates (cent)
cent -p /root/nuclei-templates install
nuclei -l hosts.txt -t /root/cent-templates

# Scan URL list (từ crawl phase)
nuclei -l urls.txt \
  -t exposures/ -t vulnerabilities/ -t misconfiguration/ \
  -json -o nuclei_urls.jsonl
```

**Nuclei template sources:**
- Official: [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- Community: [xm1k3/cent](https://github.com/xm1k3/cent) — tổng hợp community templates

#### afrog

```bash
# Fast PoC scanner, bổ sung cho nuclei
afrog -t https://target.com \
  -severity critical,high \
  -json-output afrog.jsonl
```

| Tool | Ưu điểm | Nhược điểm |
|------|---------|-----------|
| **Nuclei** | YAML templates, dễ custom, community lớn | Cần update templates thường xuyên |
| **afrog** | PoC-based, accurate | Template ít hơn nuclei |

### 4.2 Commercial Scanners (Deep Scan)

Dùng sau recon phase — tốn thời gian nhưng coverage cao cho web vulns.

| Scanner | Repo/Tool | Use case |
|---------|-----------|----------|
| **Acunetix** | [kienzx203/acunetix23](https://github.com/kienzx203/acunetix23) | Full DAST, SQLi/XSS/SSRF detection |
| **Nessus** | [kienzx203/nessus_oneclick](https://github.com/kienzx203/nessus_oneclick) | Network + CVE scanning |

**Workflow thực tế:**
```
Nuclei (fast, automated) → Verify findings manually → Acunetix/Nessus (deep scan selected targets)
```

---

## Execution Order — k1nzr3con.yaml Kill Chain

Tất cả tools dưới đây đã được tích hợp vào `k1nzr3con.yaml`.  
Dấu `[OFF]` = disabled by default, bật bằng `--vars`.

```
L01  PASSIVE + ACTIVE RECON  (7 parallel, always on)
     subfinder, assetfinder, findomain, chaos, sublist3r, gobuster_dns, oneforall
       |
L02-04 POST-PROCESS + MERGE (normalize + dedup)
       |
L05  DNS RESOLVE
     dnsx → subdomains_resolved.txt
       |
L06  PORT SCAN + PASSIVE URLS  (5 parallel)
     naabu (fast sweep)          run_portscan=true
     subzy (takeover check)      always
     gau (passive URLs)          run_crawl=true
     waybackurls                 run_crawl=true
     deep_portscan [OFF]         run_deep_scan=false  (rustscan + nmap, hours)
       |
L07  HTTP PROBE
     httpx → httpx.jsonl (title + tech-detect + status)
       |
L08  ATTACK SURFACE EXPANSION  (5 parallel)
     dirbrute         run_dirbrute=true  (gobuster+ffuf+feroxbuster+dirsearch+fuzzuli+swaggerspy)
     vhost_fuzz        run_vhost=true    (gobuster vhost + ffuf)
     katana            run_crawl=true    (JS-aware crawl)
     screenshot        run_screenshot=true (gowitness)
     kiterunner [OFF]  run_params=false  (API route discovery — Assetnote wordlists)
       |
L09  MERGE + GALLERY  (2 parallel)
     merge_urls → urls_all.txt + urls_params.txt
     screenshot_gallery → gallery.html
       |
L10  VULNERABILITY SCAN  (4 parallel)
     nuclei            run_nuclei=true   (template-based, all live hosts)
     nuclei_urls       run_nuclei=true   (templates on crawled endpoints)
     afrog [OFF]       run_afrog=false   (PoC-based, complements nuclei)
     param_discover [OFF] run_params=false
       └─ fanout: arjun + x8 + fallparams  (hidden params on urls_params.txt)
       |
L11  REPORT
     nuclei_report → nuclei_report/summary.md
     k1nzr3c0n HTML report → GET /runs/{id}/report
```

### Bật thêm tools theo nhu cầu

```bash
# Bật toàn bộ (deep scan + param discovery + afrog)
k1nzr3c0n run -w workflows/k1nzr3con.yaml -t target.com \
  --vars run_deep_scan=true run_params=true run_afrog=true

# Chỉ bật hidden param + API route
k1nzr3c0n run -w workflows/k1nzr3con.yaml -t target.com \
  --vars run_params=true

# Chỉ bật afrog (nhanh hơn deep scan)
k1nzr3c0n run -w workflows/k1nzr3con.yaml -t target.com \
  --vars run_afrog=true

# Dùng wordlist lớn hơn cho param discovery
k1nzr3c0n run -w workflows/k1nzr3con.yaml -t target.com \
  --vars run_params=true param_wordlist=/app/wordlists/params-large.txt

# Lightweight — chỉ recon + port + http (không crawl, không screenshot)
k1nzr3c0n run -w workflows/k1nzr3con.yaml -t target.com \
  --vars run_crawl=false run_screenshot=false run_dirbrute=false
```

---

## API Keys Setup (subfinder config)

```yaml
# ~/.config/subfinder/provider-config.yaml
chaos:
  - YOUR_CHAOS_KEY
shodan:
  - YOUR_SHODAN_KEY
censys:
  - YOUR_CENSYS_ID:YOUR_CENSYS_SECRET
securitytrails:
  - YOUR_ST_KEY
binaryedge:
  - YOUR_BE_KEY
virustotal:
  - YOUR_VT_KEY
fullhunt:
  - YOUR_FH_KEY
netlas:
  - YOUR_NETLAS_KEY
```

---

## Wordlists Reference

```bash
# Subdomain bruteforce
/app/wordlists/subdomains-top1million-110000.txt   # gobuster dns default
/app/wordlists/best-dns-wordlist.txt               # alterative

# Directory/path bruteforce
/app/wordlists/directory-list-2.3-medium.txt       # standard
/app/wordlists/raft-large-files.txt                # files
/app/wordlists/api-endpoints.txt                   # APIs

# Parameter discovery
/app/wordlists/arjun-large.txt
/app/wordlists/params-small.txt

# vhost fuzzing
/app/wordlists/vhosts-top1000.txt
```

---

*Cập nhật lần cuối: 2026-07 | k1nzr3c0n v3.1*
