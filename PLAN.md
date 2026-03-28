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

### Phase 4 — Spider / site crawling

The built-in modules currently only scan the single URL provided via `-t`. They don't follow links, discover subpages, or probe common paths. A spider pre-phase fixes this.

**Design:** The spider is a separate pre-phase, not a module — it discovers URLs, it doesn't produce findings. It runs before any modules, and feeds the discovered URL list into the existing module pipeline.

**Flow:** `spider crawls site` → `discovered URL list` → `each module runs against each URL` → `deduplicate findings` → `report`

**Key decisions:**
- Modules stay unchanged — they already work on one URL. The runner calls them once per discovered URL instead of once total
- Off by default — enabled via `--spider` flag so existing behavior is preserved
- Same-origin scope — only follows links on the same host
- All spider traffic uses `logged_request()` and appears in the HTTP log as `module: "spider"`

**Spider implementation (`webscan/spider.py`):**
- BFS crawl starting from target URL
- HTML link extraction: `<a href>`, `<form action>`, `<link href>`, `<script src>`, `<iframe src>`
- URL normalization via `urllib.parse.urljoin`, deduplication, fragment stripping
- Scope enforcement: same-origin (scheme+host+port) by default, configurable
- robots.txt respect via `urllib.robotparser.RobotFileParser`
- Concurrency via `ThreadPoolExecutor` with rate limiting
- Outputs: `spider-results.json` (full metadata) + `spider-urls.txt` (one URL per line, for external tools)

**Configuration (`config/default.yaml` spider section):**
```yaml
spider:
  enabled: false
  max_depth: 3
  max_pages: 50
  scope: "same-origin"    # same-origin | same-domain | subdomain
  respect_robots: true
  rate_limit: 10          # requests/second
  timeout: 300
  workers: 5
  exclude_patterns: []    # regex patterns to skip, e.g. "/logout", "\.pdf$"
```

**CLI integration (`webscan/cli.py`):**
- New flags: `--spider / --no-spider`, `--spider-depth N`, `--spider-max-pages N`
- Spider runs after config build / scan_dir creation, before module execution
- Module targets expand: each URL-type module gets one invocation per discovered URL
- Display: `"Spider found 23 pages (depth 3, 1.2s)"`

**Runner changes (`webscan/runner.py`):**
- No structural change needed — it already handles `list[tuple[BaseModule, str]]`
- 20 URLs × 4 modules = 80 entries in the pool (naturally parallel)
- Progress display groups by module name: `"headers (5/20 URLs)..."`
- Each module instance is fresh per URL (instance state like `_raw_output_path` stays isolated)

**Finding deduplication (`webscan/dedup.py`):**
- Group findings by `(title, severity, category, source)`
- Consolidate duplicates: keep one finding, add `metadata["affected_urls"]` list and `metadata["occurrence_count"]`
- "Missing HSTS header" on 20 pages becomes one finding with "Found on 20 pages"
- Controlled by config flag, on by default when spider is enabled

**External tool support:**
- nuclei: supports `-l urls.txt` — switch from `-u` to `-l` when spider URL file exists
- nikto: supports `-host` with a file — same adaptation
- sqlmap: discovered URLs with query parameters fed as individual targets
- ffuf: no change needed (does its own path discovery via wordlists)

**Data model additions (`webscan/models.py`):**
- `@dataclass UrlMeta`: url, status_code, content_type, depth, discovered_from
- `@dataclass SpiderResult`: urls, url_metadata, robots_disallowed, duration_seconds, pages_crawled, start_url
- `ScanResult` gets optional `spider_result` field for inclusion in reports

**Report updates:**
- Spider summary in report header (pages crawled, depth, duration)
- "Discovered Pages" section in HTML report with URL tree
- Findings with `occurrence_count` display "Found on N pages" instead of repeating

**Two-tier spider strategy:**

The built-in spider (this phase) is lightweight and dependency-free but has limitations. ZAP (Phase 5) has a full-featured spider with JS rendering and auth support. Both feed into the same `SpiderResult` interface, so the rest of the pipeline (modules, dedup, reports) doesn't care which spider produced the URL list.

| | Built-in spider (Phase 4) | ZAP spider (Phase 5) |
|---|---|---|
| **Dependencies** | None (pure Python, stdlib) | Java + ZAP daemon |
| **HTML crawling** | Yes | Yes |
| **JavaScript/SPA** | No — can't execute JS | Yes — AJAX spider uses headless browser |
| **Authenticated crawling** | No | Yes — ZAP session management |
| **Speed** | Fast (lightweight) | Slower (full browser for AJAX spider) |
| **When to use** | Quick scans, CI pipelines, no Java available | Full assessments, SPAs, auth-protected sites |

The CLI selects the spider backend automatically: uses ZAP's spider if ZAP is running and available, otherwise falls back to the built-in spider. Users can force one or the other via config:

```yaml
spider:
  backend: "auto"       # auto | builtin | zap
```

When `backend: "auto"`:
1. Check if ZAP daemon is reachable (default `http://localhost:8080`)
2. If yes → use ZAP's traditional spider + AJAX spider, convert results to `SpiderResult`
3. If no → use built-in spider

This means the built-in spider is never wasted work — it serves as the always-available fallback and the fast option for CI, while ZAP provides the deep crawl when available.

**Known limitations (built-in spider v1):**
- No JavaScript rendering — SPA link discovery is limited (ZAP's AJAX spider covers this)
- No authenticated crawling — pages behind login return 302/401 (ZAP covers this)
- Session module makes 10 requests per URL — may need reduced sample size when spidering many pages

**Implementation order:**
1. `webscan/models.py` — add `UrlMeta`, `SpiderResult`
2. `config/default.yaml` — add `spider:` section
3. `webscan/spider.py` — BFS crawl, link extraction, scope/depth/robots
4. `webscan/dedup.py` — finding deduplication
5. `webscan/cli.py` — `--spider` flags, pre-phase insertion, target expansion
6. `webscan/runner.py` — progress display for multi-URL runs
7. External tool modules — `-l` URL file support
8. `webscan/report.py` — spider summary, occurrence count display
9. Tests — `test_spider.py`, `test_dedup.py`

### Phase 5 — Advanced integrations

**ZAP integration (`webscan/modules/zap.py`):**
- Connects to ZAP daemon via REST API (`http://localhost:8080` by default)
- Active scan: XSS, CSRF, session fixation, file upload, auth bypass
- Spider integration: ZAP's traditional spider + AJAX spider feed into `SpiderResult`, used as the spider backend when `spider.backend` is `"auto"` or `"zap"`
- Session management: ZAP handles authenticated crawling via configured contexts
- Configuration: `zap.api_key`, `zap.address`, `zap.port`, `zap.context`

Other advanced integrations:
33. New custom module: `jwt.py` — algorithm confusion, weak secrets, missing expiry
34. New custom module: `graphql.py` — introspection, query depth, batch abuse
35. Lynis module (server-side auditing)
36. Authenticated scanning support (session tokens in config, multi-user auth contexts)

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
