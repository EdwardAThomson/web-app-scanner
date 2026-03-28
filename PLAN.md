# `webscan` — Web App Security Testing Orchestrator

## Context

No single open source tool covers the full web app pentest workflow. Running tools individually, correlating results manually, and dealing with different output formats is tedious. This project builds a Python CLI that wraps existing tools, adds custom modules where gaps exist, and produces unified reports.

## Architecture

**CLI framework:** Click (already installed, good subcommand support) + Rich (terminal formatting)

**Module system:** Each tool gets a module that inherits from `BaseModule`. Modules implement `run(target) -> ModuleResult` and `parse_output(raw) -> list[Finding]`. Explicit dict-based registry — no auto-discovery magic.

**Execution:** `ThreadPoolExecutor` runs independent modules in parallel groups. A `--serial` flag forces sequential execution.

**Config:** CLI flags only for MVP. YAML config (default -> user -> CLI override) in Phase 2.

**Dependencies:** `click`, `rich`, `pyyaml` — that's it. `jinja2` optional for HTML reports.

## Data Model (`webscan/models.py`)

```python
Finding:     title, severity, category, source, description, location, evidence, remediation, reference, metadata
ModuleResult: module_name, success, findings[], error, duration_seconds, tool_version, raw_output_path
ScanResult:  target, started_at, finished_at, module_results[]
```

Severity: critical/high/medium/low/info. Category: tls/vulnerability/misconfiguration/secret/dependency/code/header/injection/fuzzing/auth.

## Project Structure

```
web-app-scanner/
├── pyproject.toml
├── webscan/
│   ├── __init__.py
│   ├── cli.py              # Click entry point
│   ├── config.py           # Config loading
│   ├── models.py           # Finding, ModuleResult, ScanResult
│   ├── runner.py           # Serial/parallel execution engine
│   ├── report.py           # JSON/HTML report generation
│   ├── utils.py            # Tool detection, subprocess helpers
│   └── modules/
│       ├── __init__.py     # Registry + DEFAULT_ORDER + PARALLEL_GROUPS
│       ├── base.py         # BaseModule ABC
│       ├── testssl.py      # Wraps testssl.sh (JSON output)
│       ├── nuclei.py       # Wraps Nuclei (JSONL output)
│       ├── nikto.py        # Wraps Nikto (JSON output)
│       ├── semgrep.py      # Wraps Semgrep (JSON output)
│       ├── trivy.py        # Wraps Trivy (JSON output)
│       ├── gitleaks.py     # Wraps Gitleaks (JSON output)
│       ├── ffuf.py         # Wraps ffuf (JSON output)
│       ├── sqlmap.py       # Wraps SQLMap (text parsing — no clean JSON)
│       ├── headers.py      # Custom: HTTP security headers, cookies, robots.txt, security.txt
│       ├── api_routes.py   # Custom: route discovery + auth testing (pure Python)
│       ├── disclosure.py   # Custom: HTML comments, emails, IPs, SRI (pure Python)
│       ├── session.py      # Custom: session ID entropy + cookie analysis (pure Python)
│       ├── forms.py        # Custom: form security (autocomplete, CSRF, masking)
│       ├── lynis.py        # Optional: server auditing
│       └── zap.py          # Future: ZAP REST API integration
├── config/
│   └── default.yaml
├── templates/
│   └── report.html.j2     # Phase 3
└── tests/
    ├── conftest.py
    ├── test_models.py
    ├── test_runner.py
    ├── fixtures/           # Captured real tool outputs for parse testing
    └── modules/
```

## CLI Interface

```
webscan check                     # Tool installation status table
webscan run all -t <url>          # Full scan, parallel by default
webscan run all --serial          # Full scan, sequential
webscan run tls -t <url>          # Single module
webscan run tls nuclei headers    # Multiple modules
webscan run all --skip sqlmap     # Skip specific modules
webscan report <results.json>    # Regenerate report from saved results
```

## Parallel Execution Groups

```
Group 1 (independent):  testssl, gitleaks, semgrep, trivy, headers
Group 2 (remote scan):  nuclei, nikto
Group 3 (fuzzing):      ffuf
Group 4 (targeted):     sqlmap (benefits from earlier findings)
```

## Phased Build

### Phase 1 — MVP (complete)
1. Project scaffold: `pyproject.toml`, directory structure, `cli.py` skeleton
2. Data models: `Finding`, `ModuleResult`, `ScanResult` + tests
3. `BaseModule` ABC + module registry
4. `headers` module (pure Python, no external deps — validates full pipeline)
5. `testssl` wrapper (clean JSON output, good first external tool)
6. `nuclei` + `gitleaks` wrappers
7. Serial runner + JSON report output
8. `webscan check` command with Rich table
9. End-to-end manual testing

### Phase 2 — Full coverage (complete)
10. Remaining wrappers: nikto, semgrep, trivy, ffuf, sqlmap
11. YAML config with three-layer merge
12. Parallel execution via ThreadPoolExecutor + PARALLEL_GROUPS
13. `api_routes` custom module
14. Rich progress bars and summary tables in CLI
15. Dual-target routing (`-t` for URL modules, `-s` for source modules)
16. All tools installed from source + smoke tested (including local test server)

### Phase 2b — Checklist integration (complete)
17. Extended `headers` module: Cache-Control, server banners, X-Permitted-Cross-Domain-Policies, cookie Domain, charset, Date clock, ETag inode, COOP/CORP, CSP frame-ancestors, security.txt, robots.txt, crossdomain.xml
18. Checklist data model (`webscan/checklist.py`) — 80+ items mapped to modules, coverage levels, and severity
19. New custom module: `disclosure.py` — HTML comments, email scraping, internal IPs, SRI checks
20. New custom module: `session.py` — session ID entropy analysis, cookie attribute review, predictability detection
21. New custom module: `forms.py` — autocomplete, password masking, CSRF tokens, login form analysis
22. Modernized checklist: deprecated items (HPKP, X-XSS-Protection), added modern threats (SSRF, JWT, GraphQL, prototype pollution, SRI, BOLA/IDOR, HTTP smuggling)

### Phase 3 — Reporting and CI (in progress)
23. Multi-format reports: JSON (always), HTML (Jinja2), Markdown, CSV, PDF (WeasyPrint), XLSX (openpyxl) — via `-f` flag
24. Checklist coverage shown in CLI output and all report formats
25. Severity-based exit codes (for CI)
26. Finding deduplication across tools
27. Baseline diff mode (`--diff` to compare against previous scan)

### Phase 4 — Advanced integrations
27. ZAP integration (daemon + REST API) — covers XSS, CSRF, session fixation, file upload, auth bypass
28. New custom module: `jwt.py` — algorithm confusion, weak secrets, missing expiry
29. New custom module: `graphql.py` — introspection, query depth, batch abuse
30. Lynis module (server-side auditing)
31. Authenticated scanning support (session tokens in config, multi-user auth contexts)

## Key Design Decisions

- **Dataclasses over Pydantic:** zero extra deps, data flows one direction, trivial to migrate later
- **Explicit registry over auto-discovery:** ~12 modules doesn't justify importlib complexity
- **ThreadPoolExecutor over asyncio:** work is subprocess I/O, threads are simpler and correct
- **Parallel groups over dependency DAG:** actual dependencies are simple sequential groups, not a graph
- **Temp files for tool output:** many tools write to files anyway, standardizing on this simplifies parsing and debugging

## Verification

- `pip install -e .` then `webscan check` shows tool status table
- `webscan run headers -t https://example.com` produces JSON with findings
- `webscan run all -t https://example.com` runs full workflow and writes report
- `pytest` passes all unit tests (fixture-based parse testing for each module)
