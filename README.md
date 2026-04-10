# webscan

A security testing orchestrator for web applications. Wraps open source tools and custom checks into a single CLI with unified reporting.

## What it does

- Runs 16 security modules against your web apps and source code
- Checks against a 150+ item security checklist (based on OWASP, modernized)
- Produces reports in JSON, HTML, Markdown, CSV, PDF, and Excel
- Baseline diff mode (`--diff`) compares scans to show new, fixed, and persistent findings
- CI-friendly exit codes (`--fail-on`) to gate deployments on finding severity
- Cross-module finding deduplication — same issue from multiple tools appears once
- Logs all HTTP requests for evidence and audit
- All external tools are open source, cloned and built from source
- Works with any combination of tools installed — missing tools are skipped gracefully

## Disclaimer

This tool is intended for **authorized security testing only**. Only scan targets you own or have explicit written permission to test. Unauthorized scanning of systems you do not own may violate applicable laws.

webscan orchestrates third-party open source tools, each with their own licenses and limitations. You are responsible for understanding and complying with each tool's terms of use. Use of this software and all dependent tools is entirely at your own risk — see [LICENSE](LICENSE).

## Quick start

```bash
# Install webscan
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Install external tools (clones and builds from source)
webscan install

# Check what's installed
webscan check

# Scan a live site
webscan run all -t https://your-site.com

# Scan source code
webscan run all -s /path/to/your/repo

# Scan both (recommended for full coverage)
webscan run all -t https://your-site.com -s /path/to/your/repo

# Generate HTML and PDF reports
webscan run all -t https://your-site.com -f html -f pdf

# Compare against a previous scan
webscan run all -t https://your-site.com --diff ./webscan-results/previous/webscan-*.json

# Fail CI if high or critical findings exist
webscan run all -t https://your-site.com --fail-on high
```

## Installing tools

webscan has 16 modules. 8 are built-in (pure Python, no dependencies). 8 wrap external open source tools that need to be installed separately.

**You don't need all tools installed to use webscan.** If a tool is missing, its module is skipped and the scan continues with the remaining modules. The report shows which modules ran and which were skipped.

There are two ways to install the external tools:

### Automated (recommended)

```bash
webscan install              # Install all missing tools
webscan install nuclei ffuf  # Install specific tools
webscan install --force      # Re-install everything
```

This clones each tool's source code into `tools/`, builds it locally, and links the binary into your virtualenv. It checks for prerequisites first and tells you what's missing.

### Manual

See the step-by-step instructions in [USAGE.md](USAGE.md).

### Prerequisites

The external tools have these build dependencies:

| Dependency | Required for | How to install |
|------------|-------------|----------------|
| **git** | All external tools | Usually pre-installed on Linux/macOS |
| **Go 1.22+** | nuclei, gitleaks, trivy, ffuf | `curl -sL https://go.dev/dl/go1.24.1.linux-amd64.tar.gz \| tar -C $HOME -xz` |
| **Perl 5** | nikto | Usually pre-installed on Linux/macOS |
| **Python 3.10+** | semgrep, sqlmap, webscan itself | Required |

If Go is not installed, the 4 Go-based tools will be skipped. The remaining 12 modules (including all 8 built-in modules) work without Go.

If no external tools are installed at all, the 8 built-in modules still run:

- **headers** — security headers, cookies, CORS, HTTPS enforcement, server version/CVE detection, robots.txt, security.txt
- **disclosure** — HTML comments, emails, internal IPs, API keys in pages/JS
- **forms** — autocomplete, CSRF tokens, password masking
- **session** — session ID entropy, predictability, cookie attributes
- **api_routes** — route discovery and unauthenticated access testing
- **deps** — npm dependency supply chain audit
- **genai** — generative AI integration security (chatbot detection, prompt injection surfaces, AI-related data exposure)
- **spider** — site crawling with configurable depth, page limits, and robots.txt respect

## Modules

| Module | Type | Tool | What it checks |
|--------|------|------|----------------|
| spider | Remote | built-in | Site crawling, link discovery, page enumeration |
| headers | Remote | built-in | Security headers, cookies, CORS, HTTPS, server version/CVE detection |
| disclosure | Remote | built-in | HTML comments, emails, internal IPs, API keys, SRI |
| forms | Remote | built-in | Autocomplete, CSRF tokens, password masking |
| session | Remote | built-in | Session ID entropy, predictability, cookie attributes |
| genai | Remote | built-in | AI chatbot detection, prompt injection surfaces, AI data exposure |
| api_routes | Both | built-in | Route discovery from source + unauth access testing |
| deps | Local | built-in | Typosquats, lifecycle scripts, package popularity, suspicious code |
| testssl | Remote | [testssl.sh](https://github.com/testssl/testssl.sh) | TLS/SSL protocols, ciphers, certificates |
| nuclei | Remote | [Nuclei](https://github.com/projectdiscovery/nuclei) | CVEs, misconfigurations, exposures (template-based) |
| nikto | Remote | [Nikto](https://github.com/sullo/nikto) | Web server misconfigurations |
| ffuf | Remote | [ffuf](https://github.com/ffuf/ffuf) | Directory and file discovery |
| sqlmap | Remote | [SQLMap](https://github.com/sqlmapproject/sqlmap) | SQL injection |
| semgrep | Local | [Semgrep](https://github.com/semgrep/semgrep) | Static code analysis (XSS, injection, insecure patterns) |
| trivy | Local | [Trivy](https://github.com/aquasecurity/trivy) | Dependency vulnerabilities, container scanning |
| gitleaks | Local | [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets in git history |

## Reports

Reports include:

- Severity breakdown (critical/high/medium/low/info)
- Checklist coverage (tested, passed, issues found, manual review needed)
- Modules run and modules not run
- Individual findings with evidence and remediation (deduplicated across modules)
- Baseline diff section when `--diff` is used (new, fixed, persistent findings)
- Passed checks (tested and found no issues)
- Raw findings export (`findings-raw.json`) — complete unprocessed list before dedup
- HTTP request/response log

## Try it out

A deliberately vulnerable test server is included so you can see webscan in action without scanning anything external:

```bash
# Start the test server (runs on http://127.0.0.1:8999)
python tests/test_server.py &

# Scan it with the built-in modules (no external tools needed)
webscan run spider headers disclosure forms session genai -t http://127.0.0.1:8999 -f html

# Open the HTML report in your browser
```

The test server has weak headers, missing CSRF tokens, exposed API keys, weak session IDs, and more — each vulnerability is annotated with which module detects it.

## Documentation

- [USAGE.md](USAGE.md) — Detailed usage guide
- [TOOL-REFERENCE.md](TOOL-REFERENCE.md) — Tool details, licenses, local vs remote
- [CHECKLIST-MAPPING.md](CHECKLIST-MAPPING.md) — Full checklist-to-tool mapping
- [PLAN.md](PLAN.md) — Development roadmap

## License

Apache License 2.0 — see [LICENSE](LICENSE).
