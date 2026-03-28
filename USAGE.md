# Usage Guide

## Installation

### 1. Set up Python environment

```bash
git clone <repo-url> web-app-scanner
cd web-app-scanner
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

At this point webscan is usable — the 6 built-in modules (headers, disclosure, forms, session, api_routes, deps) work immediately with no external dependencies:

```bash
webscan run headers disclosure forms session -t https://your-site.com
```

### 2. Install external tools (optional but recommended)

webscan wraps 8 external open source tools for deeper scanning (TLS analysis, vulnerability templates, fuzzing, SQL injection, static analysis, etc.). These are optional — **if a tool is missing, its module is skipped and the scan continues with everything else.**

You can install them automatically or manually.

#### Automated installation (recommended)

```bash
webscan install
```

This checks prerequisites, clones each tool from source into `tools/`, builds it locally, and links the binary into your virtualenv. It tells you what it's doing and what's missing.

```bash
webscan install nuclei ffuf    # Install just specific tools
webscan install --force         # Re-install everything from scratch
webscan check                   # See what's installed
```

#### Prerequisites for external tools

| Dependency | Required for | Notes |
|------------|-------------|-------|
| **git** | All external tools | Usually pre-installed |
| **Go 1.22+** | nuclei, gitleaks, trivy, ffuf | 4 tools need Go to compile from source |
| **Perl 5** | nikto | Usually pre-installed on Linux/macOS |

**If Go is not installed**, those 4 tools will be skipped. The remaining 10 modules still work. You can install Go without root access:

```bash
curl -sL https://go.dev/dl/go1.24.1.linux-amd64.tar.gz -o /tmp/go.tar.gz
tar -C $HOME -xzf /tmp/go.tar.gz
export GOROOT=$HOME/go
export GOPATH=$HOME/gopath
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
```

Then run `webscan install` again and it will pick up Go and build the remaining tools.

#### What works without any external tools

Even with zero external tools installed, webscan runs 6 built-in modules:

| Module | What it checks |
|--------|---------------|
| headers | Security headers, cookies, CORS, HTTPS enforcement, robots.txt, security.txt, server banners |
| disclosure | HTML comments, emails, internal IPs, API keys in pages/JS, SRI |
| forms | Autocomplete, CSRF tokens, password masking, login form security |
| session | Session ID entropy, predictability, cookie attributes |
| api_routes | Route discovery from source, unauthenticated access testing |
| deps | npm dependency supply chain audit (typosquats, lifecycle scripts, popularity) |

#### Manual installation

If you prefer to install tools yourself, or if `webscan install` fails for your environment:

<details>
<summary>Manual installation steps</summary>

```bash
# testssl.sh (bash script, no build needed)
git clone --depth 1 https://github.com/testssl/testssl.sh.git tools/testssl.sh
ln -sf $(pwd)/tools/testssl.sh/testssl.sh .venv/bin/testssl.sh

# Nuclei
git clone --depth 1 https://github.com/projectdiscovery/nuclei.git tools/nuclei
cd tools/nuclei/cmd/nuclei && go build -o ../../../../.venv/bin/nuclei . && cd ../../../..

# Gitleaks
git clone --depth 1 https://github.com/gitleaks/gitleaks.git tools/gitleaks
cd tools/gitleaks && go build -o ../../.venv/bin/gitleaks . && cd ../..

# Trivy (pinned to v0.58.2 for Go 1.24 compatibility)
git clone --depth 1 --branch v0.58.2 https://github.com/aquasecurity/trivy.git tools/trivy
cd tools/trivy && go build -o ../../.venv/bin/trivy ./cmd/trivy && cd ../..

# ffuf
git clone --depth 1 https://github.com/ffuf/ffuf.git tools/ffuf
cd tools/ffuf && go build -o ../../.venv/bin/ffuf . && cd ../..

# Nikto (Perl script + modules)
git clone --depth 1 https://github.com/sullo/nikto.git tools/nikto
ln -sf $(pwd)/tools/nikto/program/nikto.pl .venv/bin/nikto.pl
cpan -T JSON XML::Writer

# SQLMap (Python script)
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git tools/sqlmap
ln -sf $(pwd)/tools/sqlmap/sqlmap.py .venv/bin/sqlmap

# Semgrep (Python package)
.venv/bin/pip install semgrep
```

</details>

---

## Running scans

### Basic commands

```bash
# Scan a remote web application
webscan run all -t https://your-site.com

# Scan local source code
webscan run all -s /path/to/project

# Scan both (full coverage)
webscan run all -t https://your-site.com -s /path/to/project
```

### Running specific modules

```bash
# Only headers and TLS
webscan run headers testssl -t https://your-site.com

# Only source code checks
webscan run semgrep trivy gitleaks deps -s /path/to/project

# Everything except sqlmap (which is more intrusive)
webscan run all -t https://your-site.com --skip sqlmap
```

### Target flags

| Flag | What it provides | Used by |
|------|-----------------|---------|
| `-t` / `--target` | URL of the deployed site | Remote modules (headers, nuclei, nikto, etc.) |
| `-s` / `--source` | Path to source code / repo | Local modules (semgrep, trivy, gitleaks, deps) |

If a module doesn't have the flag it needs, it is skipped with a message:
```
Skipping gitleaks (needs -s/--source)
```

The `api_routes` module benefits from both flags: it discovers routes from source (`-s`) and tests them against the live site (`-t`).

---

## Report formats

Use `-f` to specify output formats (can be repeated). JSON is always generated.

```bash
# HTML report (dark-themed, browsable)
webscan run all -t https://your-site.com -f html

# Multiple formats
webscan run all -t https://your-site.com -f html -f pdf -f csv

# All formats
webscan run all -t https://your-site.com -f html -f md -f csv -f pdf -f xlsx
```

| Format | Flag | Description |
|--------|------|-------------|
| JSON | (always) | Structured data, machine-readable |
| HTML | `-f html` | Self-contained dark-themed report with navigation |
| Markdown | `-f md` | Portable text report with tables |
| CSV | `-f csv` | Findings table, importable into spreadsheets |
| PDF | `-f pdf` | Print-ready report (rendered from HTML) |
| Excel | `-f xlsx` | Two-sheet workbook (Summary + Findings, color-coded) |

### What the report contains

- **Summary** — severity breakdown cards (critical/high/medium/low/info)
- **Module results** — which modules ran, their status, finding counts, durations
- **Checklist coverage** — how many of the 150+ checklist items were tested, how many passed, how many had issues, what was skipped and why
- **Findings** — grouped by severity, each with description, location, evidence, remediation
- **Passed checks** — items that were tested and found no issues
- **Modules run / not run** — at a glance, which tools were included

---

## Configuration

### CLI flags (highest priority)

```bash
webscan run all -t https://site.com -o ./reports -f html --skip sqlmap --serial
```

### YAML config file

```bash
webscan run all -t https://site.com -c my-config.yaml
```

Example config file:

```yaml
output_dir: "./reports"
output_format: "json"

modules:
  testssl:
    timeout: 600
  nuclei:
    severity: "medium,high,critical"
    templates:
      - cves/
      - misconfigurations/
  ffuf:
    wordlist: /usr/share/wordlists/dirb/common.txt
    threads: 40
  sqlmap:
    enabled: false  # Opt-in (potentially destructive)
    level: 2
    risk: 1
```

### Config priority

Settings are merged in this order (last wins):

1. `config/default.yaml` — shipped defaults
2. `~/.config/webscan/config.yaml` — user overrides
3. `-c config.yaml` — per-scan config file
4. CLI flags — highest priority

---

## Execution modes

### Parallel (default)

Modules run in parallel groups:

```
Group 1 (independent):  testssl, gitleaks, semgrep, trivy, deps, headers,
                        disclosure, forms, session, api_routes
Group 2 (remote scan):  nuclei, nikto
Group 3 (fuzzing):      ffuf
Group 4 (targeted):     sqlmap
```

Groups run sequentially. Modules within a group run concurrently.

### Serial

```bash
webscan run all -t https://your-site.com --serial
```

Forces all modules to run one at a time. Useful for debugging or when you want to see output in order.

---

## HTTP logging

Every HTTP request made by the built-in modules (headers, disclosure, forms, session, api_routes) is logged to a JSONL file:

```
webscan-results/http-log-2026-03-28T15-18-10.jsonl
```

Each line contains: timestamp, module, method, URL, request headers, response status, response headers, body preview (first 2KB), and duration.

This serves as an evidence trail — similar to Burp Suite's HTTP history.

---

## Supply chain auditing

The `deps` module audits npm dependencies before or after installation:

```bash
# Pre-install audit (package.json only, no node_modules needed)
webscan run deps -s /path/to/project

# Post-install audit (also scans node_modules for suspicious code)
webscan run deps -s /path/to/project  # after npm install
```

Checks performed:

- **Typosquat detection** — flags packages 1-2 characters different from popular packages
- **Lifecycle scripts** — finds preinstall/postinstall hooks in your project and dependencies
- **Package popularity** — flags packages with under 1,000 weekly npm downloads
- **Suspicious code** — scans installed packages for .env reads, homedir access, eval(), base64, SSH keys
- **npm audit** — runs `npm audit` and parses results (requires package-lock.json)

---

## Local test server

A deliberately vulnerable test server is included for safe local testing:

```bash
python tests/test_server.py
# Starts on http://127.0.0.1:8999
```

Endpoints include weak headers, SQL injection, exposed .env, missing CSRF tokens, weak session IDs, and more. Each endpoint is annotated with which webscan module exercises it.

```bash
# Run custom modules against it
webscan run headers disclosure forms session -t http://127.0.0.1:8999 -f html
```

---

## Safety

- **Remote modules** send HTTP requests to the target. Only scan sites you own or have authorization to test.
- **sqlmap** actively attempts SQL injection — it is disabled by default in the config and must be explicitly included.
- **ffuf** sends many requests rapidly — use responsibly and with appropriate thread settings.
- **Local modules** (semgrep, trivy, gitleaks, deps) make no network requests to the target — they only analyze files on disk.
- The `deps` module queries the npm registry API for download counts — this is read-only public data.
