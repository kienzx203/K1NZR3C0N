# K1NZR3C0N

Automated recon pipeline for bug bounty. Runs security tools in a coordinated workflow, stores results in a web UI, and exposes findings as structured files ready for analysis.

> **Legal:** Only use against targets you own or have explicit written permission to test. The authors take no responsibility for unauthorized use.

---

## Architecture

```
Browser → FastAPI (app) → SQLite (runs.db)
                ↓
           Redis queue
                ↓
         Celery worker  ←→  /app/runs/<target>/<timestamp>/
         Celery beat (schedules)
```

- **Backend**: FastAPI + SQLite — manages runs, streams logs, serves the React UI
- **Worker**: Celery — executes workflow steps, writes output files
- **Frontend**: React — run dashboard, live log stream, file explorer with per-format renderers
- **Skills**: Qwen Code v0.21.0 installed in container, two custom skills pre-loaded

---

## Quick Start

```bash
# Clone and enter
git clone <repo> && cd K1NZR3C0N

# Create .env (see Environment section below)
cp .env.example .env

# Start everything
bash up.sh
# → installs Qwen Code on host (if not present)
# → syncs .qwen/skills/ to ~/.qwen/skills/
# → docker compose up -d

# Open UI
open http://127.0.0.1:8000
```

> First run downloads nuclei templates (~13k) into a persistent Docker volume. Subsequent starts are instant.

### Docker only (skip Qwen host install)

```bash
docker compose up -d
```

---

## Environment

Create `.env` in the project root (gitignored, never commit):

```env
# Raises GitHub API rate limit from 60 → 5,000 req/hr for tool update checks
# Create at: https://github.com/settings/tokens (no scopes needed)
GITHUB_TOKEN=github_pat_...

# Web UI bind address (default: localhost only)
HOST=127.0.0.1
PORT=8000
```

---

## Workflow Templates

Three templates ship out of the box, selectable from the UI when creating a run.

### 01 — Full Recon Pipeline

Full-coverage recon from subdomain discovery to vulnerability scanning.

```
Passive subdomain (subfinder/amass/chaos/findomain)
→ DNS brute (gobuster/shuffledns/puredns)
→ Permutation (dnsgen/alterx)
→ Port scan (rustscan/nmap)
→ HTTP probe (httpx) + CDN check (cdncheck)
→ URL crawl (katana/gau/waybackurls)
→ JS analysis (subjs/linkfinder/secretfinder)
→ Subdomain takeover (subzy/subjack/dnstake)
→ Cloud storage (S3Scanner)
→ Vuln scan (nuclei 13k templates / afrog)
→ ASN/CIDR mapping (asnmap)
```

**Key vars** (override at run time):

| Var | Default | Purpose |
|---|---|---|
| `run_passive` | `true` | Enable passive subdomain sources |
| `run_active_dns` | `true` | Enable DNS brute force |
| `run_permutation` | `true` | Enable subdomain permutation |
| `run_portscan` | `true` | Enable port scanning |
| `run_nuclei` | `true` | Enable nuclei vuln scan |
| `sub_wordlist` | `subdomains-top1million-20000.txt` | Subdomain wordlist |
| `naabu_rate` | `1500` | Naabu packet rate |
| `chaos_key` | _(empty)_ | ProjectDiscovery Chaos API key |

---

### 02 — JS & Secrets Recon

Focused on JavaScript files, secrets embedded in client-side code, and directory brute force.

```
HTTP probe (httpx)
→ Archive fetch (gau/waymore/waybackurls)
→ Secret scan (trufflehog/gitleaks)
→ Nuclei (api-keys/exposures/js-files templates)
→ JS endpoint extraction (linkfinder/jsubfinder/secretfinder)
→ GF pattern matching (sqli/xss/ssrf/lfi/…)
→ Dir brute (dirsearch/feroxbuster/ffuf/gobuster)
→ Report
```

**Key vars:**

| Var | Default | Purpose |
|---|---|---|
| `run_archive` | `true` | Fetch URLs from Wayback/gau/waymore |
| `run_secretfinder` | `true` | JS secret scanner |
| `run_nuclei_js` | `true` | Nuclei JS-specific templates |
| `run_gf` | `true` | GF pattern matching on collected URLs |
| `session_cookie` | _(empty)_ | Auth cookie for authenticated scans |
| `auth_header` | _(empty)_ | Auth header (e.g. `Bearer <token>`) |

---

### 03 — Authenticated Parameter Discovery

Discovers hidden parameters on authenticated endpoints.

```
URL collection (fallparams/gau/katana)
→ Extract existing params
→ Brute force (arjun/x8/ffuf) with session/token headers
→ Report
```

**Key vars:**

| Var | Default | Purpose |
|---|---|---|
| `session_cookie` | _(empty)_ | Session cookie |
| `auth_header` | _(empty)_ | Authorization header |
| `custom_header` | _(empty)_ | Any additional header |
| `method` | `GET` | HTTP method |
| `run_fallparams` | `true` | Enable fallparams |
| `run_gau` | `true` | Fetch URLs via gau |

---

## Workflow YAML Format

Workflows live in `workflows/`. Steps run in dependency order; independent steps run concurrently.

```yaml
name: my-workflow
description: 'What this does'
vars:
  my_flag: 'true'
  wordlist: /app/wordlists/common.txt

steps:
  - id: probe
    name: HTTP probe
    when: '{vars.my_flag}'           # skip step if value is falsy
    optional: true                   # don't fail run if this step fails
    skip_if_exists: true             # skip if output already exists (resume support)
    run: 'httpx -l {workspace}/subs.txt -o {workspace}/alive.txt'
    outputs:
      alive: '{workspace}/alive.txt'

  - id: scan
    depends_on: ['probe']            # runs after probe completes
    run: 'nuclei -l {steps.probe.alive} -jsonl -o {workspace}/nuclei.jsonl'
    outputs:
      findings: '{workspace}/nuclei.jsonl'
    requires:
      - path: '{workspace}/nuclei.jsonl'
        min_bytes: 1                 # fail step if output is empty
```

### Template variables

| Pattern | Resolves to |
|---|---|
| `{target}` | The target domain/IP |
| `{workspace}` | `runs/<target>/<timestamp>/` |
| `{vars.name}` | Workflow var (or run-time override) |
| `{steps.id.output_key}` | Output path from a previous step |

> `timeout:` values do not support `{vars.*}` — use a literal (`timeout: 60s`).
> Inside `run:` shell commands, use `$VAR` bash syntax for shell variables.

---

## Tool Arsenal

All tools are installed in the Docker image. No host dependencies required.

| Category | Tools |
|---|---|
| **Subdomain Enum** | `subfinder` `amass` `assetfinder` `findomain` `sublist3r` `chaos` `OneForAll` |
| **DNS Resolution** | `dnsx` `puredns` `shuffledns` `massdns` `gobuster(dns)` `dnsgen` `alterx` |
| **Port Scanning** | `naabu` `rustscan` `nmap` `masscan` |
| **HTTP Probing** | `httpx` `cdncheck` `tlsx` `whatweb` `wafw00f` `wpscan` |
| **URL & JS** | `katana` `gau` `waymore` `waybackurls` `hakrawler` `gospider` `cariddi` `subjs` `linkfinder` `jsubfinder` `jsapiscan` `urlfinder` |
| **Secrets** | `trufflehog` `gitleaks` `secretfinder` |
| **Param Discovery** | `arjun` `x8` `ffuf` `fallparams` `paramspider` `kiterunner` |
| **Dir Brute** | `feroxbuster` `dirsearch` `gobuster(dir)` `ffuf` |
| **Vuln Scanning** | `nuclei` (13,391 templates) `afrog` `dalfox` `crlfuzz` `corsy` `tplmap` |
| **Takeover** | `subzy` `subjack` `dnstake` |
| **Cloud & OSINT** | `S3Scanner` `cloud_enum` `asnmap` `metabigor` `uncover` `cvemap` |
| **Utilities** | `gf` `anew` `unfurl` `qsreplace` `meg` `interactsh-client` `notify` |

---

## Output Files

Each run creates `runs/<target>/<timestamp>/`:

| File | Format | Content |
|---|---|---|
| `stats.txt` | Plain text | Run summary, tech stack |
| `nuclei.jsonl` | JSONL | Vulnerability findings |
| `httpx_probe.jsonl` | JSONL | Live hosts with status, title, tech |
| `feroxbuster.json` | JSONL-in-.json | Directory brute results |
| `ffuf_paths.json` | JSON `{results:[]}` | FFuf path discovery |
| `arjun.json` | JSON `{url:{params:[]}}` | Parameters per URL |
| `naabu*.jsonl` | JSONL | Open ports |
| `gau.txt` / `katana.txt` | Plain text | Collected URLs |
| `secretfinder.txt` | Plain text | JS secrets/tokens |
| `trufflehog.json` | JSON | Credential findings |
| `gitleaks.json` | JSON | Git secret findings |
| `*_subs.txt` | Plain text | Subdomains (per tool) |
| `gowitness/` | Directory | Screenshots (PNG per URL) |
| `gf_*.txt` | Plain text | GF pattern matches |

The file explorer in the UI renders each format with a dedicated viewer — sortable tables for JSON findings, structured columns for text outputs, image gallery for screenshots.

---

## Qwen Code Integration

Qwen Code v0.21.0 is installed inside the Docker container and on the host via `up.sh`.

Two custom skills are pre-loaded:

| Skill | Purpose |
|---|---|
| `k1nzr3c0n-analyst` | Red team analyst — reads run logs, triages attack surface, correlates findings across all output files and SQLite without HTTP |
| `k1nzr3c0n-js-analyst` | JS specialist — finds all JS files (webpack chunks, sourcemaps), extracts endpoints, maps API surface, assesses auth mechanisms |

```bash
# Use inside the worker container
docker exec -it k1nzr3c0n-worker-1 bash
qwen
# → skills are auto-loaded
# → "analyze the last run for target.com"
```

Add new skills: place `SKILL.md` under `.qwen/skills/<name>/` and run `bash up.sh`.

---

## Project Structure

```
K1NZR3C0N/
├── docker-compose.yml           # 4 services: app, worker, beat, redis
├── Dockerfile                   # multi-stage: gobuilder → uibuilder → runtime
├── up.sh                        # Qwen install + skill sync + docker compose up
├── .env                         # secrets — gitignored, never commit
├── workflows/
│   ├── 01-full-recon-pipeline.yaml
│   ├── 02-js-secrets-recon.yaml
│   ├── 03-param-discovery.yaml
│   └── ARSENAL.md               # manual recon reference (passive sources, tools)
├── .qwen/skills/
│   ├── k1nzr3c0n-analyst/SKILL.md
│   └── k1nzr3c0n-js-analyst/SKILL.md
├── src/k1nzr3c0n/
│   ├── api/                     # FastAPI routes
│   ├── tasks.py                 # Celery task definitions
│   ├── tools.py                 # Tool wrapper + version check
│   └── workflow/                # YAML parser + executor
├── frontend/src/components/
│   └── FileExplorer.jsx         # 26-component file renderer
├── wordlists/                   # bundled wordlists (subdomains, dirs, params, routes)
└── runs/                        # run outputs + k1nzr3c0n.db — gitignored
```

---

## Docker Volumes

| Volume | Mount | Purpose |
|---|---|---|
| `./runs` | `/app/runs` | Run outputs + SQLite DB |
| `./workflows` | `/app/workflows` | Hot-reload workflows (no rebuild needed) |
| `./.qwen/skills` | `/root/.qwen/skills` (ro) | Qwen skill sync |
| `nuclei_data` | `/root/nuclei-templates` | Nuclei templates — persist across restarts |
| `redis_data` | Redis internal | Task queue persistence |
| `beat_data` | Celery beat internal | Schedule state |

---

## Rebuilding the Image

Required when: Dockerfile changes (new tool, dependency update).

```bash
docker compose build --no-cache
docker compose up -d
```

Templates in `nuclei_data` survive rebuilds — no re-download needed.

---

## Adding a Workflow

1. Create `workflows/my-workflow.yaml` with `name`, `description`, `vars`, `steps`
2. The UI picks it up immediately — no restart needed (volume-mounted)
3. Use `{target}`, `{workspace}`, `{vars.*}`, `{steps.<id>.<output>}` in `run:` commands
