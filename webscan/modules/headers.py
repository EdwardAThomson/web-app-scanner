"""HTTP security headers analysis module (pure Python).

Checks security headers, cookies, server banners, CORS, CSP quality,
and fetches well-known files (robots.txt, security.txt, crossdomain.xml).
"""

import json
import re
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone
from http.client import HTTPResponse

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule
from webscan.http_log import log_entry, logged_request


# Required security headers and their missing-header findings
HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "description": "HSTS not set — browsers will allow HTTP connections",
        "remediation": "Add Strict-Transport-Security header with max-age >= 31536000 and includeSubDomains",
        "severity": Severity.HIGH,
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    },
    "Content-Security-Policy": {
        "description": "No Content-Security-Policy header — vulnerable to XSS and data injection",
        "remediation": "Add a Content-Security-Policy header. Start with a report-only policy to avoid breaking functionality.",
        "severity": Severity.MEDIUM,
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    },
    "X-Content-Type-Options": {
        "description": "X-Content-Type-Options not set — browsers may MIME-sniff responses",
        "remediation": "Add X-Content-Type-Options: nosniff",
        "severity": Severity.LOW,
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "X-Frame-Options": {
        "description": "X-Frame-Options not set — page may be embedded in iframes (clickjacking)",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive",
        "severity": Severity.MEDIUM,
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
    },
    "Referrer-Policy": {
        "description": "Referrer-Policy not set — full URLs may leak in Referer headers",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin (or stricter)",
        "severity": Severity.LOW,
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "description": "Permissions-Policy not set — browser features (camera, mic, geolocation) not restricted",
        "remediation": "Add Permissions-Policy header to restrict unnecessary browser features",
        "severity": Severity.LOW,
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "X-Permitted-Cross-Domain-Policies not set — Flash/Acrobat may load cross-domain data",
        "remediation": "Add X-Permitted-Cross-Domain-Policies: none",
        "severity": Severity.LOW,
        "reference": "https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Cross-Origin-Opener-Policy (COOP) not set — page may be accessed by cross-origin popups",
        "remediation": "Add Cross-Origin-Opener-Policy: same-origin",
        "severity": Severity.LOW,
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Cross-Origin-Resource-Policy (CORP) not set — resources may be embedded by other origins",
        "remediation": "Add Cross-Origin-Resource-Policy: same-origin (or same-site)",
        "severity": Severity.LOW,
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
    },
}

# Headers that disclose server technology (information leakage)
BANNER_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime",
    "X-Version",
]


class HeadersModule(BaseModule):
    name = "headers"
    tool_binary = ""
    description = "HTTP security headers analysis"

    def check_installed(self) -> tuple[bool, str]:
        return True, "built-in"

    def get_version(self) -> str:
        return "built-in"

    def execute(self, target: str) -> list[Finding]:
        headers = self._fetch_headers(target)
        self._save_raw_output(
            json.dumps({"target": target, "headers": headers}, indent=2),
            "headers-raw.json",
        )
        findings = self.parse_output(headers)

        # Additional checks that fetch separate URLs
        findings.extend(self._check_https_enforcement(target))
        findings.extend(self._check_robots_txt(target))
        findings.extend(self._check_security_txt(target))
        findings.extend(self._check_crossdomain_xml(target))
        findings.extend(self._check_cors_reflection(target))

        return findings

    def _fetch_headers(self, target: str) -> dict[str, str]:
        """Fetch response headers from target URL."""
        result = logged_request(target, module_name=self.name)
        if result is None:
            return {}
        _status, _body, headers = result
        return headers

    def _fetch_url(self, url: str) -> tuple[int, str, dict[str, str]] | None:
        """Fetch a URL and return (status, body, headers), or None on error."""
        return logged_request(url, module_name=self.name, timeout=15)

    def parse_output(self, headers: dict[str, str]) -> list[Finding]:
        """Analyze response headers and return findings."""
        findings = []
        location = self.config.get("target", "")

        # Check for missing security headers
        for header_name, check in HEADER_CHECKS.items():
            value = _get_header(headers, header_name)
            if not value:
                # Special case: X-Frame-Options is OK if CSP frame-ancestors is set
                if header_name == "X-Frame-Options":
                    csp = _get_header(headers, "Content-Security-Policy")
                    if csp and "frame-ancestors" in csp.lower():
                        continue
                findings.append(Finding(
                    title=f"Missing {header_name} header",
                    severity=check["severity"],
                    category=Category.HEADER,
                    source=self.name,
                    description=check["description"],
                    location=location,
                    remediation=check["remediation"],
                    reference=check["reference"],
                ))

        # Check HSTS quality if present
        hsts = _get_header(headers, "Strict-Transport-Security")
        if hsts:
            findings.extend(self._check_hsts(hsts))

        # Check CSP quality if present
        csp = _get_header(headers, "Content-Security-Policy")
        if csp:
            findings.extend(self._check_csp(csp))

        # Check CORS
        acao = _get_header(headers, "Access-Control-Allow-Origin")
        if acao:
            findings.extend(self._check_cors(acao, headers))

        # Check cookies
        findings.extend(self._check_cookies(headers))

        # Check X-Content-Type-Options value
        xcto = _get_header(headers, "X-Content-Type-Options")
        if xcto and xcto.strip().lower() != "nosniff":
            findings.append(Finding(
                title="X-Content-Type-Options has invalid value",
                severity=Severity.LOW,
                category=Category.HEADER,
                source=self.name,
                description=f"Expected 'nosniff', got '{xcto.strip()}'",
                location=location,
                remediation="Set X-Content-Type-Options: nosniff",
            ))

        # Server banner / technology disclosure
        findings.extend(self._check_banners(headers))

        # Cache-Control
        findings.extend(self._check_cache_control(headers))

        # Content-Type charset
        findings.extend(self._check_charset(headers))

        # ETag inode disclosure
        findings.extend(self._check_etag(headers))

        # Date header clock check
        findings.extend(self._check_clock(headers))

        return findings

    def _check_hsts(self, value: str) -> list[Finding]:
        findings = []
        location = self.config.get("target", "")
        lower = value.lower()

        if "max-age" in lower:
            try:
                max_age = int(lower.split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:
                    findings.append(Finding(
                        title="HSTS max-age is too short",
                        severity=Severity.MEDIUM,
                        category=Category.HEADER,
                        source=self.name,
                        description=f"HSTS max-age is {max_age}s ({max_age // 86400} days). Recommended minimum is 31536000 (1 year).",
                        location=location,
                        evidence=f"Strict-Transport-Security: {value}",
                        remediation="Set max-age to at least 31536000 (1 year)",
                    ))
            except (ValueError, IndexError):
                findings.append(Finding(
                    title="HSTS max-age could not be parsed",
                    severity=Severity.LOW,
                    category=Category.HEADER,
                    source=self.name,
                    description="Could not parse max-age from HSTS header",
                    location=location,
                    evidence=f"Strict-Transport-Security: {value}",
                    remediation="Ensure HSTS header has a valid max-age directive",
                ))

        if "includesubdomains" not in lower:
            findings.append(Finding(
                title="HSTS missing includeSubDomains",
                severity=Severity.LOW,
                category=Category.HEADER,
                source=self.name,
                description="HSTS does not include subdomains, leaving them vulnerable to downgrade attacks",
                location=location,
                evidence=f"Strict-Transport-Security: {value}",
                remediation="Add includeSubDomains to HSTS header",
            ))

        return findings

    def _check_csp(self, value: str) -> list[Finding]:
        findings = []
        location = self.config.get("target", "")
        lower = value.lower()

        dangerous_directives = {
            "unsafe-inline": ("CSP allows unsafe-inline", Severity.MEDIUM,
                              "unsafe-inline in script-src allows inline scripts, weakening XSS protection"),
            "unsafe-eval": ("CSP allows unsafe-eval", Severity.MEDIUM,
                            "unsafe-eval allows eval() and similar, enabling code injection"),
        }

        for directive, (title, severity, desc) in dangerous_directives.items():
            if directive in lower:
                findings.append(Finding(
                    title=title,
                    severity=severity,
                    category=Category.HEADER,
                    source=self.name,
                    description=desc,
                    location=location,
                    evidence=f"Content-Security-Policy: {value}",
                    remediation=f"Remove '{directive}' from CSP and use nonces or hashes instead",
                ))

        if "default-src" not in lower and "script-src" not in lower:
            findings.append(Finding(
                title="CSP missing default-src and script-src",
                severity=Severity.MEDIUM,
                category=Category.HEADER,
                source=self.name,
                description="CSP has neither default-src nor script-src — scripts can load from any origin",
                location=location,
                evidence=f"Content-Security-Policy: {value}",
                remediation="Add at least a default-src or script-src directive",
            ))

        for directive in ["default-src", "script-src"]:
            if directive in lower:
                directive_value = lower.split(directive)[1].split(";")[0]
                if "*" in directive_value and "'none'" not in directive_value:
                    findings.append(Finding(
                        title=f"CSP {directive} contains wildcard",
                        severity=Severity.HIGH,
                        category=Category.HEADER,
                        source=self.name,
                        description=f"Wildcard in {directive} allows scripts from any origin",
                        location=location,
                        evidence=f"Content-Security-Policy: {value}",
                        remediation=f"Replace wildcard in {directive} with specific allowed origins",
                    ))

        return findings

    def _check_cors(self, acao: str, headers: dict[str, str]) -> list[Finding]:
        findings = []
        location = self.config.get("target", "")

        if acao.strip() == "*":
            acac = _get_header(headers, "Access-Control-Allow-Credentials")
            if acac and acac.strip().lower() == "true":
                findings.append(Finding(
                    title="CORS allows all origins with credentials",
                    severity=Severity.CRITICAL,
                    category=Category.HEADER,
                    source=self.name,
                    description="Access-Control-Allow-Origin: * combined with Allow-Credentials: true is a severe misconfiguration",
                    location=location,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrict allowed origins to specific trusted domains",
                ))
            else:
                findings.append(Finding(
                    title="CORS allows all origins",
                    severity=Severity.MEDIUM,
                    category=Category.HEADER,
                    source=self.name,
                    description="Access-Control-Allow-Origin is set to wildcard (*)",
                    location=location,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrict allowed origins to specific trusted domains if the API handles sensitive data",
                ))

        return findings

    def _check_cookies(self, headers: dict[str, str]) -> list[Finding]:
        findings = []
        location = self.config.get("target", "")

        cookies = []
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                cookies.append(value)

        for cookie in cookies:
            lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()

            if "secure" not in lower:
                findings.append(Finding(
                    title=f"Cookie '{cookie_name}' missing Secure flag",
                    severity=Severity.MEDIUM,
                    category=Category.HEADER,
                    source=self.name,
                    description="Cookie can be sent over unencrypted HTTP connections",
                    location=location,
                    evidence=f"Set-Cookie: {cookie}",
                    remediation="Add the Secure flag to this cookie",
                ))

            if "httponly" not in lower:
                findings.append(Finding(
                    title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    category=Category.HEADER,
                    source=self.name,
                    description="Cookie is accessible via JavaScript, increasing XSS impact",
                    location=location,
                    evidence=f"Set-Cookie: {cookie}",
                    remediation="Add the HttpOnly flag to this cookie",
                ))

            if "samesite" not in lower:
                findings.append(Finding(
                    title=f"Cookie '{cookie_name}' missing SameSite attribute",
                    severity=Severity.LOW,
                    category=Category.HEADER,
                    source=self.name,
                    description="Cookie does not have SameSite attribute, may be sent with cross-site requests",
                    location=location,
                    evidence=f"Set-Cookie: {cookie}",
                    remediation="Add SameSite=Lax or SameSite=Strict to this cookie",
                ))

            # Check for overly broad Domain attribute
            domain_match = re.search(r"domain=([^;]+)", lower)
            if domain_match:
                domain = domain_match.group(1).strip()
                if domain.startswith("."):
                    findings.append(Finding(
                        title=f"Cookie '{cookie_name}' accessible by all subdomains",
                        severity=Severity.MEDIUM,
                        category=Category.HEADER,
                        source=self.name,
                        description=f"Cookie Domain is set to '{domain}', making it accessible to all subdomains",
                        location=location,
                        evidence=f"Set-Cookie: {cookie}",
                        remediation="Restrict cookie Domain to the specific hostname if subdomain access is not needed",
                    ))

        return findings

    def _check_banners(self, headers: dict[str, str]) -> list[Finding]:
        """Check for server technology disclosure in response headers."""
        findings = []
        location = self.config.get("target", "")

        for header_name in BANNER_HEADERS:
            value = _get_header(headers, header_name)
            if value:
                findings.append(Finding(
                    title=f"Server technology disclosed via {header_name} header",
                    severity=Severity.LOW,
                    category=Category.MISCONFIGURATION,
                    source=self.name,
                    description=f"{header_name} header reveals server technology: {value.strip()}",
                    location=location,
                    evidence=f"{header_name}: {value.strip()}",
                    remediation=f"Remove or suppress the {header_name} header to avoid disclosing server technology",
                ))

        return findings

    def _check_cache_control(self, headers: dict[str, str]) -> list[Finding]:
        """Check for missing or weak Cache-Control headers."""
        findings = []
        location = self.config.get("target", "")

        cc = _get_header(headers, "Cache-Control")
        pragma = _get_header(headers, "Pragma")

        if not cc:
            findings.append(Finding(
                title="Missing Cache-Control header",
                severity=Severity.MEDIUM,
                category=Category.HEADER,
                source=self.name,
                description="No Cache-Control header set — browsers may cache sensitive responses",
                location=location,
                remediation="Add Cache-Control: no-store for sensitive pages, or appropriate caching directives for public content",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
            ))
        elif cc:
            lower = cc.lower()
            if "no-store" not in lower and "no-cache" not in lower and "private" not in lower:
                findings.append(Finding(
                    title="Cache-Control may allow caching of sensitive data",
                    severity=Severity.LOW,
                    category=Category.HEADER,
                    source=self.name,
                    description=f"Cache-Control does not prevent caching: {cc.strip()}",
                    location=location,
                    evidence=f"Cache-Control: {cc.strip()}",
                    remediation="For sensitive pages, use Cache-Control: no-store",
                ))

        return findings

    def _check_charset(self, headers: dict[str, str]) -> list[Finding]:
        """Check if Content-Type specifies a character set."""
        findings = []
        location = self.config.get("target", "")

        ct = _get_header(headers, "Content-Type")
        if ct and "text/html" in ct.lower() and "charset" not in ct.lower():
            findings.append(Finding(
                title="Content-Type missing charset",
                severity=Severity.LOW,
                category=Category.HEADER,
                source=self.name,
                description="HTML Content-Type does not specify charset, which may allow character encoding attacks",
                location=location,
                evidence=f"Content-Type: {ct.strip()}",
                remediation="Add charset=utf-8 to the Content-Type header",
            ))

        return findings

    def _check_etag(self, headers: dict[str, str]) -> list[Finding]:
        """Check for Apache-style ETag headers that leak inode numbers."""
        findings = []
        location = self.config.get("target", "")

        etag = _get_header(headers, "ETag")
        if etag:
            # Apache inode-style ETags look like "inode-size-timestamp" in hex
            # e.g., "2a-5f-63b1c8a0" or "1234a-5678b-9abcd"
            stripped = etag.strip().strip('"').strip("W/").strip('"')
            parts = stripped.split("-")
            if len(parts) == 3 and all(re.match(r'^[0-9a-f]+$', p, re.IGNORECASE) for p in parts):
                findings.append(Finding(
                    title="ETag header may disclose inode information",
                    severity=Severity.LOW,
                    category=Category.MISCONFIGURATION,
                    source=self.name,
                    description="ETag appears to contain Apache-style inode-size-timestamp values",
                    location=location,
                    evidence=f"ETag: {etag.strip()}",
                    remediation="Configure Apache with FileETag MTime Size (remove Inode) or use FileETag None",
                    reference="https://httpd.apache.org/docs/2.4/mod/core.html#fileetag",
                ))

        return findings

    def _check_clock(self, headers: dict[str, str]) -> list[Finding]:
        """Check if the server clock is reasonably synchronised."""
        findings = []
        location = self.config.get("target", "")

        date_header = _get_header(headers, "Date")
        if date_header:
            try:
                from email.utils import parsedate_to_datetime
                server_time = parsedate_to_datetime(date_header)
                now = datetime.now(timezone.utc)
                skew = abs((now - server_time).total_seconds())
                if skew > 300:  # More than 5 minutes off
                    findings.append(Finding(
                        title="Server clock is not synchronised",
                        severity=Severity.LOW,
                        category=Category.MISCONFIGURATION,
                        source=self.name,
                        description=f"Server time differs from UTC by {int(skew)} seconds ({int(skew // 60)} minutes)",
                        location=location,
                        evidence=f"Date: {date_header.strip()}",
                        remediation="Configure NTP to keep the server clock synchronised",
                    ))
            except (ValueError, TypeError):
                pass

        return findings

    def _check_cors_reflection(self, target: str) -> list[Finding]:
        """Check if the server reflects arbitrary Origin headers in CORS responses.

        This is different from wildcard CORS — the server dynamically echoes
        back whatever Origin is sent, which bypasses browser same-origin policy.
        """
        findings = []
        fake_origin = "https://evil-attacker-test.com"

        try:
            result = logged_request(
                target, module_name=self.name, timeout=15,
                headers={"Origin": fake_origin},
            )
            if result is not None:
                _status, _body, resp_headers = result
                acao = resp_headers.get("Access-Control-Allow-Origin", "")
                acac = resp_headers.get("Access-Control-Allow-Credentials", "")

                if acao.strip() == fake_origin:
                    if acac and acac.strip().lower() == "true":
                        findings.append(Finding(
                            title="CORS reflects arbitrary Origin with credentials",
                            severity=Severity.CRITICAL,
                            category=Category.HEADER,
                            source=self.name,
                            description="Server reflects the Origin header in Access-Control-Allow-Origin and allows credentials. "
                                        "Any website can make authenticated cross-origin requests.",
                            location=target,
                            evidence=f"Sent Origin: {fake_origin}, Got ACAO: {acao}, ACAC: {acac}",
                            remediation="Validate Origin against an allowlist instead of reflecting it. Never combine reflected Origin with Allow-Credentials: true.",
                        ))
                    else:
                        findings.append(Finding(
                            title="CORS reflects arbitrary Origin",
                            severity=Severity.MEDIUM,
                            category=Category.HEADER,
                            source=self.name,
                            description="Server reflects the Origin header in Access-Control-Allow-Origin. "
                                        "While credentials are not allowed, this may still enable data theft for public endpoints.",
                            location=target,
                            evidence=f"Sent Origin: {fake_origin}, Got ACAO: {acao}",
                            remediation="Validate Origin against an allowlist of trusted domains",
                        ))
        except Exception:
            pass

        return findings

    def _check_https_enforcement(self, target: str) -> list[Finding]:
        """Check whether the site enforces HTTPS properly.

        Tests:
        1. If target is HTTPS: does HTTP version exist? If so, does it redirect to HTTPS?
        2. If target is HTTP: does HTTPS version exist? If not, flag as no HTTPS at all.
        3. Is the redirect permanent (301) or temporary (302)?
        """
        findings = []
        from urllib.parse import urlparse

        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        path = parsed.path or "/"

        if parsed.scheme == "https":
            # Target is HTTPS — check if HTTP is also accessible
            http_url = f"http://{hostname}{':' + str(parsed.port) if parsed.port and parsed.port != 443 else ''}{path}"
            try:
                # Don't follow redirects — we want to see the redirect itself
                import http.client
                import time as _time
                _start = _time.time()
                req_hdrs = {"User-Agent": "webscan/0.1.0", "Host": hostname}
                conn = http.client.HTTPConnection(hostname, parsed.port or 80, timeout=10)
                conn.request("GET", path, headers=req_hdrs)
                resp = conn.getresponse()
                status = resp.status
                location_header = resp.getheader("Location", "")
                _dur = int((_time.time() - _start) * 1000)
                conn.close()
                log_entry(
                    url=http_url, status=status,
                    request_headers=req_hdrs,
                    response_headers={"Location": location_header} if location_header else {},
                    duration_ms=_dur, module_name=self.name,
                )

                if status == 200:
                    findings.append(Finding(
                        title="HTTP available without redirect to HTTPS",
                        severity=Severity.HIGH,
                        category=Category.MISCONFIGURATION,
                        source=self.name,
                        description=f"The site is accessible over plain HTTP ({http_url}) without redirecting to HTTPS. "
                                    "Users connecting over HTTP are vulnerable to eavesdropping and man-in-the-middle attacks.",
                        location=http_url,
                        evidence=f"HTTP {http_url} returned status {status} (no redirect)",
                        remediation="Configure the web server to redirect all HTTP requests to HTTPS with a 301 (permanent) redirect",
                    ))
                elif status in (301, 302, 303, 307, 308):
                    if not location_header.startswith("https://"):
                        findings.append(Finding(
                            title="HTTP redirects but not to HTTPS",
                            severity=Severity.HIGH,
                            category=Category.MISCONFIGURATION,
                            source=self.name,
                            description=f"HTTP redirects to {location_header} which is not an HTTPS URL",
                            location=http_url,
                            evidence=f"HTTP {status} -> {location_header}",
                            remediation="Ensure HTTP redirects to an HTTPS URL",
                        ))
                    elif status != 301:
                        findings.append(Finding(
                            title=f"HTTP to HTTPS redirect uses {status} instead of 301",
                            severity=Severity.LOW,
                            category=Category.MISCONFIGURATION,
                            source=self.name,
                            description=f"HTTP redirects to HTTPS with status {status}. "
                                        "A 301 (permanent) redirect is preferred so browsers cache the redirect "
                                        "and don't make the insecure request again.",
                            location=http_url,
                            evidence=f"HTTP {status} -> {location_header}",
                            remediation="Use a 301 (permanent) redirect from HTTP to HTTPS",
                        ))
                    # 301 to HTTPS = correct, no finding
            except (OSError, Exception):
                pass  # HTTP not reachable — that's fine, HTTPS-only is good

        elif parsed.scheme == "http":
            # Target is HTTP — check if HTTPS is available
            https_url = f"https://{hostname}{':' + str(parsed.port) if parsed.port and parsed.port != 80 else ''}{path}"
            try:
                result = logged_request(https_url, method="HEAD", module_name=self.name, timeout=10)
                if result is None:
                    raise OSError("HTTPS not reachable")
                findings.append(Finding(
                    title="Site accessible over HTTP but HTTPS is available",
                    severity=Severity.MEDIUM,
                    category=Category.MISCONFIGURATION,
                    source=self.name,
                    description=f"You are scanning over HTTP ({target}) but the site also supports HTTPS ({https_url}). "
                                "Consider scanning the HTTPS version and ensuring HTTP redirects to HTTPS.",
                    location=target,
                    evidence=f"Both http:// and https:// respond for {hostname}",
                    remediation="Use HTTPS for all connections. Configure HTTP to redirect to HTTPS with a 301.",
                ))
            except (urllib.error.URLError, OSError):
                # No HTTPS at all — check if site has auth indicators
                has_auth_indicators = self._has_auth_indicators(target)
                if has_auth_indicators:
                    findings.append(Finding(
                        title="No HTTPS available — HTTP-only site with authentication",
                        severity=Severity.CRITICAL,
                        category=Category.MISCONFIGURATION,
                        source=self.name,
                        description=f"The site at {hostname} does not support HTTPS and appears to handle authentication "
                                    "(cookies or login forms detected). Credentials and session tokens are transmitted in "
                                    "plaintext and can be intercepted by anyone on the network.",
                        location=target,
                        evidence=f"https://{hostname} is not reachable; authentication indicators found on HTTP",
                        remediation="Enable HTTPS with a valid TLS certificate immediately. "
                                    "Credentials are being transmitted in plaintext. Free certificates are available from Let's Encrypt.",
                        reference="https://letsencrypt.org/",
                    ))
                else:
                    findings.append(Finding(
                        title="No HTTPS available — site is HTTP only",
                        severity=Severity.HIGH,
                        category=Category.MISCONFIGURATION,
                        source=self.name,
                        description=f"The site at {hostname} does not appear to support HTTPS. "
                                    "All traffic is transmitted in plaintext. If the site handles any sensitive data "
                                    "or user input, this is a serious risk.",
                        location=target,
                        evidence=f"https://{hostname} is not reachable",
                        remediation="Enable HTTPS with a valid TLS certificate. Free certificates are available from Let's Encrypt.",
                        reference="https://letsencrypt.org/",
                    ))

        return findings

    def _has_auth_indicators(self, target: str) -> bool:
        """Check if an HTTP target shows signs of authentication.

        Looks for Set-Cookie headers and password/login forms in the response.
        """
        result = logged_request(target, module_name=self.name, timeout=10)
        if result is None:
            return False
        _status, body, headers = result

        # Check for session cookies
        for key in headers:
            if key.lower() == "set-cookie":
                return True

        # Check for login-related content
        body_lower = body.lower()
        auth_indicators = [
            'type="password"', "type='password'",
            'name="password"', "name='password'",
            'action="/login"', "action='/login'",
            "/login", "/signin", "/auth",
            "log in", "sign in", "username", "password",
        ]
        if any(indicator in body_lower for indicator in auth_indicators):
            return True

        return False

    def _check_robots_txt(self, target: str) -> list[Finding]:
        """Fetch and analyze robots.txt for sensitive path disclosure."""
        findings = []
        location = self.config.get("target", "")
        base = target.rstrip("/")
        result = self._fetch_url(f"{base}/robots.txt")

        if result is None or result[0] != 200:
            return findings

        body = result[1]
        sensitive_patterns = [
            "admin", "backup", "config", "database", "db", "debug",
            "internal", "private", "secret", "staging", "test",
            "api", "dashboard", "management", "console",
        ]

        disallowed = []
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    disallowed.append(path)

        sensitive_found = [
            p for p in disallowed
            if any(s in p.lower() for s in sensitive_patterns)
        ]

        if sensitive_found:
            findings.append(Finding(
                title="robots.txt discloses potentially sensitive paths",
                severity=Severity.LOW,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description=f"robots.txt contains {len(sensitive_found)} potentially sensitive Disallow entries",
                location=f"{base}/robots.txt",
                evidence="\n".join(f"Disallow: {p}" for p in sensitive_found[:10]),
                remediation="Review robots.txt — consider whether disallowed paths reveal sensitive application structure",
            ))

        return findings

    def _check_security_txt(self, target: str) -> list[Finding]:
        """Check for the presence of security.txt (RFC 9116)."""
        findings = []
        base = target.rstrip("/")

        # Check both locations per RFC 9116
        for path in ["/.well-known/security.txt", "/security.txt"]:
            result = self._fetch_url(f"{base}{path}")
            if result and result[0] == 200 and "contact:" in result[1].lower():
                return findings  # Found valid security.txt

        findings.append(Finding(
            title="No security.txt file found",
            severity=Severity.INFO,
            category=Category.MISCONFIGURATION,
            source=self.name,
            description="No security.txt found at /.well-known/security.txt — security researchers may not know how to report vulnerabilities",
            location=f"{base}/.well-known/security.txt",
            remediation="Add a security.txt file per RFC 9116 with at least a Contact field",
            reference="https://securitytxt.org/",
        ))

        return findings

    def _check_crossdomain_xml(self, target: str) -> list[Finding]:
        """Check for overly permissive crossdomain.xml (Flash/Silverlight)."""
        findings = []
        base = target.rstrip("/")
        result = self._fetch_url(f"{base}/crossdomain.xml")

        if result is None or result[0] != 200:
            return findings

        body = result[1]

        if 'domain="*"' in body:
            findings.append(Finding(
                title="crossdomain.xml allows access from any domain",
                severity=Severity.MEDIUM,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description="crossdomain.xml contains a wildcard domain policy, allowing any external domain to make cross-domain requests",
                location=f"{base}/crossdomain.xml",
                evidence=body[:500],
                remediation="Restrict crossdomain.xml to specific trusted domains, or remove it if Flash/Silverlight is not used",
            ))
        elif body.strip():
            findings.append(Finding(
                title="crossdomain.xml file present",
                severity=Severity.INFO,
                category=Category.MISCONFIGURATION,
                source=self.name,
                description="crossdomain.xml exists — review if it is still needed (Flash is end-of-life)",
                location=f"{base}/crossdomain.xml",
                remediation="Remove crossdomain.xml if Flash/Silverlight is no longer used",
            ))

        return findings


def _get_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None
