"""Site spider / crawler module (pure Python).

BFS crawl starting from the target URL.  Discovers pages, builds a site map,
and flags security-relevant observations:

- Sensitive paths (admin panels, backups, config endpoints)
- Broken links (4xx responses)
- Server errors (5xx responses)
- Redirect chains
- Pages behind authentication (401/403)

Outputs:
  sitemap.json  — machine-readable site map with all discovered pages
  sitemap.txt   — human-readable tree view
"""

import json
import os
import re
import time
from collections import defaultdict, deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule
from webscan.http_log import logged_request

# Paths that suggest sensitive / admin content
SENSITIVE_PATH_PATTERNS = re.compile(
    r"(?:"
    # Directory/segment names (bounded by / or start/end)
    r"(?:^|/)(?:admin|administrator|manage|manager|dashboard|console"
    r"|config|configuration|settings|setup|install"
    r"|backup|old|copy|temp|tmp"
    r"|debug|trace|test|staging|dev"
    r"|phpmyadmin|adminer|phpinfo"
    r"|wp-admin|wp-login|wp-config"
    r"|server-status|server-info"
    r"|actuator|health|metrics|info"
    r"|graphql|swagger|api-docs|openapi"
    r"|elmah|trace\.axd|glimpse)(?:$|[/\?.])"
    # Dotfiles / hidden files
    r"|/\.(?:git|svn|hg|env|htaccess|htpasswd|DS_Store)"
    # Backup file extensions
    r"|\.(?:bak|backup|old|orig|save|swp|tmp|copy)(?:$|\?)"
    r")",
    re.I,
)

# Content types we should follow links from (HTML-like)
CRAWLABLE_TYPES = {"text/html", "application/xhtml+xml"}

# Default limits
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PAGES = 50
DEFAULT_DELAY = 0.2  # seconds between requests


# ---------------------------------------------------------------------------
# Robots.txt parser (simple)
# ---------------------------------------------------------------------------

class _RobotsTxt:
    """Minimal robots.txt parser — tracks Disallow rules for * and webscan."""

    def __init__(self, body: str):
        self._disallowed: list[str] = []
        self._parse(body)

    def _parse(self, body: str):
        active = False  # True when we're inside a matching User-agent block
        for line in body.splitlines():
            line = line.split("#")[0].strip()  # strip comments
            if not line:
                continue
            if line.lower().startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip().lower()
                active = agent in ("*", "webscan")
            elif active and line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    self._disallowed.append(path)

    def is_allowed(self, path: str) -> bool:
        for rule in self._disallowed:
            if path.startswith(rule):
                return False
        return True


# ---------------------------------------------------------------------------
# HTML link extractor
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Extract links from HTML."""

    LINK_ATTRS = {
        "a": "href",
        "area": "href",
        "form": "action",
        "link": "href",
        "script": "src",
        "img": "src",
        "iframe": "src",
        "source": "src",
        "video": "src",
        "audio": "src",
        "embed": "src",
        "object": "data",
    }

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.base_href: str | None = None

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        # <base href="...">
        if tag == "base" and "href" in attr_dict:
            self.base_href = attr_dict["href"]

        # <meta http-equiv="refresh" content="0;url=...">
        if tag == "meta":
            equiv = attr_dict.get("http-equiv", "").lower()
            if equiv == "refresh":
                content = attr_dict.get("content", "")
                m = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.I)
                if m:
                    self.links.append(m.group(1))

        # Standard link attributes
        link_attr = self.LINK_ATTRS.get(tag)
        if link_attr and link_attr in attr_dict:
            val = attr_dict[link_attr].strip()
            if val:
                self.links.append(val)


# ---------------------------------------------------------------------------
# Site map tree builder
# ---------------------------------------------------------------------------

def _build_tree_text(pages: list[dict], base_url: str) -> str:
    """Build a human-readable tree from discovered pages."""
    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # Build a path tree
    tree: dict = {}
    status_map: dict[str, int] = {}

    for page in sorted(pages, key=lambda p: p["url"]):
        parsed = urlparse(page["url"])
        path = parsed.path.strip("/")
        status_map[page["url"]] = page.get("status", 0)

        parts = path.split("/") if path else []
        node = tree
        for part in parts:
            if part not in node:
                node[part] = {}
            node = node[part]

    # Render
    lines = [f"{base_origin}/"]

    def render(node: dict, prefix: str, parent_path: str):
        items = sorted(node.items())
        for i, (name, children) in enumerate(items):
            is_last = i == len(items) - 1
            connector = "└── " if is_last else "├── "
            full_path = f"{parent_path}/{name}"
            full_url = f"{base_origin}{full_path}"
            status = status_map.get(full_url, "")
            status_str = f"  [{status}]" if status and status != 200 else ""
            lines.append(f"{prefix}{connector}{name}{status_str}")
            child_prefix = prefix + ("    " if is_last else "│   ")
            render(children, child_prefix, full_path)

    render(tree, "", "")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class SpiderModule(BaseModule):
    name = "spider"
    tool_binary = ""
    description = "Site crawler and sitemap generator"

    def check_installed(self) -> tuple[bool, str]:
        return True, "built-in"

    def get_version(self) -> str:
        return "built-in"

    def execute(self, target: str) -> list[Finding]:
        max_depth = self.config.get("modules", {}).get("spider", {}).get("max_depth", DEFAULT_MAX_DEPTH)
        max_pages = self.config.get("modules", {}).get("spider", {}).get("max_pages", DEFAULT_MAX_PAGES)
        delay = self.config.get("modules", {}).get("spider", {}).get("request_delay", DEFAULT_DELAY)
        respect_robots = self.config.get("modules", {}).get("spider", {}).get("respect_robots_txt", True)

        parsed_target = urlparse(target)
        origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # Fetch and parse robots.txt
        robots = None
        if respect_robots:
            robots = self._fetch_robots(origin)

        # BFS crawl
        pages = self._crawl(target, origin, robots, max_depth, max_pages, delay)

        # Write site map files
        sitemap = self._build_sitemap(target, pages, max_depth, max_pages)
        self._write_sitemap(sitemap, pages, origin)

        # Generate findings
        findings = self.parse_output(pages, target)
        return findings

    def parse_output(self, pages: list[dict] | str = "", target: str = "") -> list[Finding]:
        """Generate findings from crawl results."""
        if isinstance(pages, str):
            return []

        findings: list[Finding] = []

        # Summary
        html_pages = [p for p in pages if p.get("content_type", "").startswith("text/html")]
        findings.append(Finding(
            title=f"Spider discovered {len(pages)} URLs ({len(html_pages)} HTML pages)",
            severity=Severity.INFO,
            category=Category.MISCONFIGURATION,
            source=self.name,
            description=(
                f"The spider crawled the target site and discovered {len(pages)} unique URLs "
                f"including {len(html_pages)} HTML pages. See sitemap.json and sitemap.txt "
                "in the scan directory for the full site map."
            ),
            location=target,
            evidence=f"Total URLs: {len(pages)}, HTML pages: {len(html_pages)}",
            metadata={"total_urls": len(pages), "html_pages": len(html_pages)},
        ))

        # Sensitive paths
        sensitive: list[dict] = []
        for page in pages:
            path = urlparse(page["url"]).path
            if SENSITIVE_PATH_PATTERNS.search(path):
                sensitive.append(page)

        if sensitive:
            evidence_lines = []
            for p in sensitive[:15]:
                path = urlparse(p["url"]).path
                evidence_lines.append(f"{path}  [{p.get('status', '?')}]")

            findings.append(Finding(
                title=f"Sensitive or administrative paths discovered ({len(sensitive)})",
                severity=Severity.MEDIUM,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description=(
                    "The spider discovered paths that may expose administrative interfaces, "
                    "configuration data, or development artifacts."
                ),
                location=target,
                evidence="\n".join(evidence_lines),
                remediation=(
                    "Review each path: restrict access with authentication, remove "
                    "development/debug endpoints from production, and ensure backups "
                    "and configuration files are not web-accessible."
                ),
            ))

        # Broken links (4xx)
        broken = [p for p in pages if 400 <= p.get("status", 0) < 500 and p.get("status") != 401 and p.get("status") != 403]
        if broken:
            evidence_lines = [f"{p['url']}  [{p['status']}]" for p in broken[:10]]
            findings.append(Finding(
                title=f"Broken links found ({len(broken)} URLs returning 4xx)",
                severity=Severity.LOW,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description="Pages with client error responses indicate broken links or removed content.",
                location=target,
                evidence="\n".join(evidence_lines),
                remediation="Fix or remove broken links. Return proper 404 pages without leaking information.",
            ))

        # Server errors (5xx)
        errors = [p for p in pages if 500 <= p.get("status", 0) < 600]
        if errors:
            evidence_lines = [f"{p['url']}  [{p['status']}]" for p in errors[:10]]
            findings.append(Finding(
                title=f"Server errors detected ({len(errors)} URLs returning 5xx)",
                severity=Severity.MEDIUM,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description=(
                    "Server errors may indicate unhandled exceptions that could leak "
                    "stack traces, database details, or other sensitive information."
                ),
                location=target,
                evidence="\n".join(evidence_lines),
                remediation=(
                    "Investigate server errors. Ensure custom error pages are used "
                    "that do not expose implementation details."
                ),
            ))

        # Auth-protected pages (401/403)
        auth_protected = [p for p in pages if p.get("status") in (401, 403)]
        if auth_protected:
            evidence_lines = [f"{urlparse(p['url']).path}  [{p['status']}]" for p in auth_protected[:10]]
            findings.append(Finding(
                title=f"Authentication-protected pages found ({len(auth_protected)})",
                severity=Severity.INFO,
                category=Category.AUTH,
                source=self.name,
                description=(
                    "These pages returned 401/403, indicating they require authentication. "
                    "They should be tested with valid credentials for authorization bypass."
                ),
                location=target,
                evidence="\n".join(evidence_lines),
                remediation="Test these endpoints with authenticated sessions to check for authorization issues.",
            ))

        return findings

    # -- crawling -----------------------------------------------------------

    def _crawl(
        self,
        start_url: str,
        origin: str,
        robots: _RobotsTxt | None,
        max_depth: int,
        max_pages: int,
        delay: float,
    ) -> list[dict]:
        """BFS crawl starting from start_url."""
        queue: deque[tuple[str, int, str | None]] = deque()  # (url, depth, parent_url)
        visited: set[str] = set()
        pages: list[dict] = []

        queue.append((self._normalize_url(start_url), 0, None))

        while queue and len(pages) < max_pages:
            url, depth, parent = queue.popleft()

            if url in visited:
                continue
            visited.add(url)

            parsed = urlparse(url)

            # Same-origin check
            if f"{parsed.scheme}://{parsed.netloc}" != origin:
                continue

            # Robots.txt check
            if robots and not robots.is_allowed(parsed.path):
                continue

            # Skip non-HTTP schemes, fragments-only, mailto, tel, javascript
            if parsed.scheme not in ("http", "https"):
                continue

            # Fetch the page
            if delay > 0 and len(pages) > 0:
                time.sleep(delay)

            result = logged_request(url, module_name=self.name, timeout=15)

            if result is None:
                pages.append({
                    "url": url,
                    "status": 0,
                    "content_type": "",
                    "depth": depth,
                    "parent": parent,
                    "links": [],
                })
                continue

            status, body, headers = result
            content_type = headers.get("Content-Type", "").split(";")[0].strip().lower()

            page_entry = {
                "url": url,
                "status": status,
                "content_type": content_type,
                "depth": depth,
                "parent": parent,
                "links": [],
            }

            # Handle redirects — follow the Location header
            if status in (301, 302, 303, 307, 308):
                location = headers.get("Location", "")
                if location:
                    resolved = urljoin(url, location)
                    resolved = self._normalize_url(resolved)
                    page_entry["redirect_to"] = resolved
                    if resolved not in visited:
                        queue.append((resolved, depth, parent))

            # Extract links from HTML pages (only if within depth limit)
            if content_type in CRAWLABLE_TYPES and depth < max_depth and body:
                links = self._extract_links(body, url)
                page_entry["links"] = links

                for link in links:
                    if link not in visited:
                        queue.append((link, depth + 1, url))

            pages.append(page_entry)

        return pages

    def _extract_links(self, html: str, page_url: str) -> list[str]:
        """Extract and resolve all links from an HTML page."""
        extractor = _LinkExtractor()
        try:
            extractor.feed(html)
        except Exception:
            pass

        base = extractor.base_href or page_url
        parsed_page = urlparse(page_url)
        origin = f"{parsed_page.scheme}://{parsed_page.netloc}"

        links: list[str] = []
        seen: set[str] = set()

        for raw_link in extractor.links:
            # Skip empty, javascript:, mailto:, tel:, data:
            if not raw_link or raw_link.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                continue

            resolved = urljoin(base, raw_link)
            normalized = self._normalize_url(resolved)

            # Same-origin filter
            parsed = urlparse(normalized)
            if f"{parsed.scheme}://{parsed.netloc}" != origin:
                continue

            if normalized not in seen:
                seen.add(normalized)
                links.append(normalized)

        return links

    def _fetch_robots(self, origin: str) -> _RobotsTxt | None:
        """Fetch and parse robots.txt."""
        result = logged_request(f"{origin}/robots.txt", module_name=self.name, timeout=10)
        if result is None or result[0] != 200:
            return None
        return _RobotsTxt(result[1])

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize a URL: strip fragment, ensure trailing consistency."""
        parsed = urlparse(url)
        # Drop fragment
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",  # no fragment
        ))
        return normalized

    # -- site map output ----------------------------------------------------

    def _build_sitemap(
        self, target: str, pages: list[dict], max_depth: int, max_pages: int
    ) -> dict:
        """Build the sitemap data structure."""
        by_status: dict[str, int] = defaultdict(int)
        by_type: dict[str, int] = defaultdict(int)

        for page in pages:
            by_status[str(page.get("status", 0))] += 1
            ct = page.get("content_type", "unknown") or "unknown"
            by_type[ct] += 1

        return {
            "target": target,
            "crawled_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "config": {
                "max_depth": max_depth,
                "max_pages": max_pages,
            },
            "stats": {
                "urls_discovered": len(pages),
                "by_status": dict(sorted(by_status.items())),
                "by_content_type": dict(sorted(by_type.items())),
            },
            "pages": [
                {
                    "url": p["url"],
                    "status": p.get("status", 0),
                    "content_type": p.get("content_type", ""),
                    "depth": p.get("depth", 0),
                    "parent": p.get("parent"),
                    "links_count": len(p.get("links", [])),
                    "redirect_to": p.get("redirect_to"),
                    "assessed_by": [],  # populated by report cross-reference
                }
                for p in pages
            ],
        }

    def _write_sitemap(self, sitemap: dict, pages: list[dict], origin: str):
        """Write sitemap.json and sitemap.txt to the scan directory."""
        scan_dir = self.config.get("scan_dir", "")
        if not scan_dir:
            return

        # JSON
        json_path = os.path.join(scan_dir, "sitemap.json")
        with open(json_path, "w") as f:
            json.dump(sitemap, f, indent=2)

        # Tree text
        tree_text = _build_tree_text(pages, origin)
        txt_path = os.path.join(scan_dir, "sitemap.txt")
        with open(txt_path, "w") as f:
            f.write(tree_text)
            f.write("\n")

        self._raw_output_path = json_path
