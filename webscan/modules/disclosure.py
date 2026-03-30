"""Information disclosure module (pure Python).

Fetches web pages and checks for information leakage:
- API keys and secrets in page content and linked JavaScript files
- HTML comments containing sensitive information
- Email addresses in page content
- Internal IP addresses in responses
- Subresource Integrity (SRI) missing on CDN script/link tags
"""

import os
import re
import urllib.request
import urllib.error
import ssl
from html.parser import HTMLParser

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule
from webscan.http_log import logged_request

# Patterns
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)
# Common false-positive email domains to skip
IGNORE_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net",
    "w3.org", "schema.org", "xmlns.com",
    "sentry.io", "sentry-next.wixpress.com",
}

# API key patterns — (name, regex, severity)
# Based on common provider key formats (similar to gitleaks rules)
API_KEY_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("AWS Secret Key", re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), Severity.CRITICAL),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), Severity.CRITICAL),
    ("Stripe Secret Key", re.compile(r"sk_live_[A-Za-z0-9]{24,}"), Severity.CRITICAL),
    ("Stripe Publishable Key", re.compile(r"pk_live_[A-Za-z0-9]{24,}"), Severity.MEDIUM),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.HIGH),
    ("Slack Token", re.compile(r"xox[bpors]-[0-9a-zA-Z\-]{10,}"), Severity.CRITICAL),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), Severity.HIGH),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), Severity.HIGH),
    ("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), Severity.CRITICAL),
    ("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), Severity.HIGH),
    ("Firebase Key", re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), Severity.HIGH),
    ("Heroku API Key", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), Severity.MEDIUM),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("Generic Secret Assignment", re.compile(
        r"""(?:api_key|apikey|api_secret|secret_key|access_token|auth_token|private_key)\s*[=:]\s*['"][A-Za-z0-9_\-/+=]{16,}['"]""",
        re.IGNORECASE,
    ), Severity.HIGH),
    ("Bearer Token", re.compile(r"""['"]Bearer\s+[A-Za-z0-9_\-\.]{20,}['"]"""), Severity.HIGH),
    ("Basic Auth Hardcoded", re.compile(r"""['"]Basic\s+[A-Za-z0-9+/=]{10,}['"]"""), Severity.HIGH),
]


class _HTMLAnalyzer(HTMLParser):
    """Parse HTML to extract comments, scripts, links, and text content."""

    def __init__(self):
        super().__init__()
        self.comments: list[str] = []
        self.scripts_without_sri: list[dict] = []
        self.links_without_sri: list[dict] = []
        self.text_chunks: list[str] = []
        self._in_script = False
        self._in_style = False

    def handle_comment(self, data):
        stripped = data.strip()
        if stripped and len(stripped) > 3:
            self.comments.append(stripped)

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        if tag == "script":
            self._in_script = True
            src = attr_dict.get("src", "")
            if src and self._is_external(src) and "integrity" not in attr_dict:
                self.scripts_without_sri.append({"src": src})

        elif tag == "link":
            href = attr_dict.get("href", "")
            rel = attr_dict.get("rel", "")
            if href and "stylesheet" in rel and self._is_external(href) and "integrity" not in attr_dict:
                self.links_without_sri.append({"href": href})

        elif tag == "style":
            self._in_style = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data):
        if not self._in_script and not self._in_style:
            self.text_chunks.append(data)

    @staticmethod
    def _is_external(url: str) -> bool:
        return url.startswith("http://") or url.startswith("https://") or url.startswith("//")


SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".next", ".nuxt",
}
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".rb", ".go",
    ".java", ".php", ".json", ".yaml", ".yml", ".toml",
    ".env", ".cfg", ".ini", ".conf",
}
MAX_SOURCE_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


class DisclosureModule(BaseModule):
    name = "disclosure"
    tool_binary = ""
    description = "Information disclosure detection (HTML comments, emails, IPs, SRI)"
    target_type = "both"

    def check_installed(self) -> tuple[bool, str]:
        return True, "built-in"

    def get_version(self) -> str:
        return "built-in"

    def execute(self, target: str) -> list[Finding]:
        source_path = self.config.get("source_path", "")
        target_url = self.config.get("target", "")
        findings: list[Finding] = []

        if source_path and os.path.isdir(source_path):
            findings.extend(self._scan_source_files(source_path))

        if target_url:
            body, headers = self._fetch_page(target_url)
            if body is not None:
                self._save_raw_output(body, "disclosure-raw.txt")
                findings.extend(self.parse_output(body, target_url, headers))
                analyzer = _HTMLAnalyzer()
                try:
                    analyzer.feed(body)
                except Exception:
                    pass
                findings.extend(self._scan_js_files(analyzer, target_url))

        return findings

    def _fetch_page(self, target: str) -> tuple[str | None, dict[str, str]]:
        result = logged_request(target, module_name=self.name)
        if result is None:
            return None, {}
        _status, body, headers = result
        return body, headers

    def parse_output(self, body: str, target: str = "", headers: dict = None) -> list[Finding]:
        """Analyze page body for information disclosure."""
        findings = []
        headers = headers or {}

        # Parse HTML
        analyzer = _HTMLAnalyzer()
        try:
            analyzer.feed(body)
        except Exception:
            pass

        # Check HTML comments for sensitive content
        findings.extend(self._check_comments(analyzer.comments, target))

        # Check for email addresses
        findings.extend(self._check_emails(body, target))

        # Check for internal IP addresses in body and headers
        findings.extend(self._check_internal_ips(body, headers, target))

        # Check for missing SRI on external scripts/stylesheets
        findings.extend(self._check_sri(analyzer, target))

        # Check for API keys and secrets in page content
        findings.extend(self._check_api_keys(body, target, "page body"))

        return findings

    def _check_comments(self, comments: list[str], target: str) -> list[Finding]:
        findings = []

        sensitive_patterns = [
            "todo", "fixme", "hack", "bug", "xxx",
            "password", "passwd", "secret", "api_key", "apikey",
            "token", "credential", "private", "internal",
            "debug", "test", "staging", "dev ",
            "version", "build", "deploy",
        ]

        for comment in comments:
            lower = comment.lower()

            # Skip very short or likely template comments
            if len(comment) < 10:
                continue

            # Check for sensitive keywords
            matched = [p for p in sensitive_patterns if p in lower]
            if matched:
                findings.append(Finding(
                    title=f"HTML comment contains potentially sensitive content",
                    severity=Severity.LOW,
                    category=Category.MISCONFIGURATION,
                    source=self.name,
                    description=f"HTML comment matches sensitive keywords: {', '.join(matched)}",
                    location=target,
                    evidence=f"<!-- {comment[:200]} -->",
                    remediation="Remove HTML comments containing sensitive information before deploying to production",
                ))

        # Report if there are many comments (development artifacts)
        if len(comments) > 10:
            findings.append(Finding(
                title=f"Page contains {len(comments)} HTML comments",
                severity=Severity.INFO,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description="Large number of HTML comments may indicate development artifacts left in production",
                location=target,
                evidence=f"Found {len(comments)} HTML comments",
                remediation="Review and remove unnecessary HTML comments from production pages",
            ))

        return findings

    def _check_emails(self, body: str, target: str) -> list[Finding]:
        findings = []

        emails = set(EMAIL_RE.findall(body))
        # Filter out false positives
        real_emails = {
            e for e in emails
            if e.split("@")[1].lower() not in IGNORE_EMAIL_DOMAINS
        }

        if real_emails:
            findings.append(Finding(
                title=f"Email addresses disclosed ({len(real_emails)} found)",
                severity=Severity.LOW,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description="Email addresses found in page content may be harvested by spammers or used for social engineering",
                location=target,
                evidence=", ".join(sorted(real_emails)[:10]),
                remediation="Consider using contact forms instead of exposing email addresses, or obfuscate them",
            ))

        return findings

    def _check_internal_ips(self, body: str, headers: dict, target: str) -> list[Finding]:
        findings = []

        # Check body
        body_ips = set(INTERNAL_IP_RE.findall(body))
        # Check headers
        header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        header_ips = set(INTERNAL_IP_RE.findall(header_text))

        all_ips = body_ips | header_ips
        # Filter out common false positives
        all_ips.discard("127.0.0.1")
        all_ips.discard("0.0.0.0")

        if all_ips:
            locations = []
            if body_ips - {"127.0.0.1", "0.0.0.0"}:
                locations.append("page body")
            if header_ips - {"127.0.0.1", "0.0.0.0"}:
                locations.append("response headers")

            findings.append(Finding(
                title=f"Internal IP address(es) disclosed",
                severity=Severity.MEDIUM,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description=f"Internal/private IP addresses found in {' and '.join(locations)}",
                location=target,
                evidence=", ".join(sorted(all_ips)[:5]),
                remediation="Remove internal IP addresses from responses. Configure reverse proxies to strip internal headers.",
            ))

        return findings

    def _check_sri(self, analyzer: _HTMLAnalyzer, target: str) -> list[Finding]:
        """Check for external scripts/stylesheets loaded without Subresource Integrity."""
        findings = []

        scripts = analyzer.scripts_without_sri
        links = analyzer.links_without_sri

        if scripts:
            findings.append(Finding(
                title=f"External scripts loaded without Subresource Integrity ({len(scripts)})",
                severity=Severity.MEDIUM,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description="External JavaScript files are loaded without integrity attributes, making them vulnerable to supply chain attacks",
                location=target,
                evidence="\n".join(s["src"] for s in scripts[:5]),
                remediation="Add integrity and crossorigin attributes to external script tags",
                reference="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            ))

        if links:
            findings.append(Finding(
                title=f"External stylesheets loaded without Subresource Integrity ({len(links)})",
                severity=Severity.LOW,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description="External CSS files are loaded without integrity attributes",
                location=target,
                evidence="\n".join(l["href"] for l in links[:5]),
                remediation="Add integrity and crossorigin attributes to external link tags",
                reference="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            ))

        return findings

    def _check_api_keys(self, content: str, target: str, source_desc: str) -> list[Finding]:
        """Scan text content for API keys and secrets."""
        findings = []
        seen = set()

        for key_name, pattern, severity in API_KEY_PATTERNS:
            for match in pattern.finditer(content):
                matched_text = match.group(0)

                # Deduplicate by key type + first 10 chars of match
                dedup_key = f"{key_name}:{matched_text[:10]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Redact the matched value for the evidence field
                if len(matched_text) > 12:
                    redacted = matched_text[:6] + "..." + matched_text[-4:]
                else:
                    redacted = matched_text[:4] + "..."

                findings.append(Finding(
                    title=f"Potential {key_name} exposed in {source_desc}",
                    severity=severity,
                    category=Category.SECRET,
                    source=self.name,
                    description=f"A pattern matching {key_name} was found in {source_desc}. "
                                "If this is a real key, it should be rotated immediately.",
                    location=target,
                    evidence=f"Redacted match: {redacted}",
                    remediation=f"Remove the {key_name} from client-facing code. Use environment variables or a secrets manager. "
                                "Rotate the key if it was ever exposed publicly.",
                    metadata={
                        "key_type": key_name,
                        "source": source_desc,
                    },
                ))

        return findings

    def _scan_js_files(self, analyzer: _HTMLAnalyzer, target: str) -> list[Finding]:
        """Fetch linked JavaScript files and scan them for API keys."""
        findings = []
        base_url = target.rstrip("/")

        # Collect script URLs (both with and without SRI — keys in any JS are bad)
        script_urls = set()
        for script in analyzer.scripts_without_sri:
            script_urls.add(script["src"])

        # Limit to 10 JS files to avoid excessive requests
        for src in list(script_urls)[:10]:
            url = src
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = base_url + url
            elif not url.startswith("http"):
                url = base_url + "/" + url

            result = logged_request(url, module_name=self.name, timeout=15)
            if result is not None:
                _status, js_content, _headers = result
                if len(js_content) > 0:
                    findings.extend(self._check_api_keys(js_content, url, f"JavaScript file ({src})"))

        return findings

    # -- source-code scanning -----------------------------------------------

    def _scan_source_files(self, source_path: str) -> list[Finding]:
        """Scan local source files for information disclosure issues."""
        findings: list[Finding] = []
        for dirpath, dirnames, filenames in os.walk(source_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in SOURCE_EXTENSIONS:
                    continue
                filepath = os.path.join(dirpath, filename)
                try:
                    if os.path.getsize(filepath) > MAX_SOURCE_FILE_SIZE:
                        continue
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read()
                except OSError:
                    continue
                rel_path = os.path.relpath(filepath, source_path)
                findings.extend(self._check_api_keys(
                    content, rel_path, f"source file ({rel_path})"))
                findings.extend(self._check_emails(content, rel_path))
                findings.extend(self._check_internal_ips(content, {}, rel_path))

        self._save_raw_output(
            f"Scanned source in {source_path}\nFindings: {len(findings)}",
            "disclosure-source-raw.txt",
        )
        return findings
