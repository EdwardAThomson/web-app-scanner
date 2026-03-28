# Tool Reference — Local vs Remote

Shows which modules inspect local code/repos and which scan deployed web applications.

## Remote scanning (needs `-t <url>`)

These modules send HTTP requests to a live target. Only use against applications you own or have explicit authorization to test.

| Module | Tool | What it does |
|--------|------|-------------|
| **testssl** | testssl.sh | TLS/SSL protocol, cipher, and certificate analysis |
| **headers** | (built-in) | Security headers, cookies, CORS, HTTPS enforcement, Cache-Control, robots.txt, security.txt, crossdomain.xml, CORS reflection, server banners, ETag, clock sync |
| **disclosure** | (built-in) | HTML comments, email addresses, internal IPs, API keys in pages/JS, Subresource Integrity |
| **forms** | (built-in) | Form autocomplete, password masking, CSRF tokens, login form security, credential submission method |
| **session** | (built-in) | Session ID entropy/predictability, cookie attributes (persistent vs session, scope) |
| **nuclei** | Nuclei | Template-based vulnerability scanning (CVEs, misconfigs, exposures) |
| **nikto** | Nikto | Web server misconfiguration scanning |
| **ffuf** | ffuf | Directory/file discovery (fuzzing) |
| **sqlmap** | SQLMap | SQL injection detection and exploitation |

All built-in remote modules log their HTTP requests and responses to a JSONL file for evidence and audit.

## Local scanning (needs `-s <path>`)

These modules analyze source code, dependencies, or git history on disk.

| Module | Tool | What it does | Network access |
|--------|------|-------------|----------------|
| **semgrep** | Semgrep | Static code analysis (SAST) — XSS, injection, insecure crypto, framework patterns | Downloads rules on first run |
| **trivy** | Trivy | Dependency vulnerabilities (npm, pip, go.mod, etc.), container image scanning, IaC scanning, secret detection | Downloads vulnerability database |
| **gitleaks** | Gitleaks | Secret detection in git history — API keys, tokens, passwords | None |
| **deps** | (built-in) | Typosquats, lifecycle scripts, package popularity, suspicious code in node_modules, npm audit | Queries npm registry API for download counts |

Note: `deps` queries the public npm registry API (read-only) to check package popularity. It does not send requests to the scan target.

## Both (uses `-t` and/or `-s`)

| Module | Tool | What it does |
|--------|------|-------------|
| **api_routes** | (built-in) | Discovers routes from source code (`-s`), optionally tests them for unauthenticated access (`-t`) |

## Using both flags together

```
webscan run all -t https://my-app.com -s /path/to/repo
```

Each module receives the target type it needs. Modules that don't have the right flag are skipped with a message:
```
Skipping gitleaks (needs -s/--source)
```

## Tools by license

| Tool | License | Language | Install method |
|------|---------|----------|---------------|
| testssl.sh | GPL-2.0 | Bash | git clone |
| Nuclei | MIT | Go | clone + go build |
| Gitleaks | MIT | Go | clone + go build |
| Nikto | GPL | Perl | git clone + cpan modules |
| Semgrep | LGPL-2.1 | Python | pip |
| Trivy | Apache-2.0 | Go | clone + go build (v0.58.2) |
| ffuf | MIT | Go | clone + go build |
| SQLMap | GPL-2.0 | Python | git clone |

Built-in modules (headers, disclosure, forms, session, api_routes, deps) are pure Python with no external tool dependencies.

## Tool source locations

All external tools are cloned into `tools/` and built locally from source:

```
tools/
├── testssl.sh/    # Bash script, runs directly
├── nuclei/        # Go source, binary in .venv/bin/
├── gitleaks/      # Go source, binary in .venv/bin/
├── nikto/         # Perl script, symlinked to .venv/bin/
├── trivy/         # Go source (v0.58.2), binary in .venv/bin/
├── ffuf/          # Go source, binary in .venv/bin/
└── sqlmap/        # Python script, symlinked to .venv/bin/
```

## Safety notes

| Risk level | Modules | Why |
|------------|---------|-----|
| **Safe** | semgrep, trivy, gitleaks, deps, headers, disclosure, forms, session | Read-only analysis, no destructive actions |
| **Moderate** | testssl, nuclei, nikto, api_routes | Send probing requests but don't attempt exploitation |
| **Use with care** | ffuf | Sends many requests rapidly (configurable thread count) |
| **Potentially destructive** | sqlmap | Actively attempts SQL injection. Disabled by default in config. |
