"""Session analysis module (pure Python).

Collects session cookies from multiple requests and analyzes:
- Session ID entropy (Shannon entropy + character distribution)
- Sequential/predictable patterns
- Cookie attributes (persistent vs session, scope)
- Sensitive-looking cookie values
"""

import json
import math
import re
import ssl
import time
import urllib.error
import urllib.request
from collections import Counter

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule
from webscan.http_log import log_entry

# Common session cookie names across frameworks
SESSION_COOKIE_NAMES = {
    "sessionid", "session_id", "sessid", "sid",
    "phpsessid", "jsessionid", "aspsessionid",
    "connect.sid", "express.sid", "_session_id",
    "session", "laravel_session", "ci_session",
    "rack.session", "_csrf_token",
}

# Number of requests to collect session IDs for entropy analysis
SAMPLE_SIZE = 10

# Minimum Shannon entropy for a secure session ID (bits per character)
MIN_ENTROPY = 3.5


class SessionModule(BaseModule):
    name = "session"
    tool_binary = ""
    description = "Session cookie analysis (entropy, attributes, predictability)"

    def check_installed(self) -> tuple[bool, str]:
        return True, "built-in"

    def get_version(self) -> str:
        return "built-in"

    def execute(self, target: str) -> list[Finding]:
        # Collect session cookies from multiple requests
        samples = self._collect_sessions(target, SAMPLE_SIZE)
        if not samples:
            return []
        self._save_raw_output(
            json.dumps({"target": target, "samples": samples}, indent=2),
            "session-raw.json",
        )
        return self._analyze_sessions(samples, target)

    def _collect_sessions(self, target: str, count: int) -> list[dict]:
        """Make multiple requests and collect Set-Cookie headers.

        Returns a list of dicts, each containing all cookies from one request.
        """
        samples = []
        ctx = ssl.create_default_context()
        req_headers = {"User-Agent": "webscan/0.1.0"}

        for _ in range(count):
            start = time.time()
            try:
                req = urllib.request.Request(target, method="GET", headers=req_headers)
                with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                    duration_ms = int((time.time() - start) * 1000)
                    cookies = {}
                    for key, value in resp.headers.items():
                        if key.lower() == "set-cookie":
                            name = value.split("=")[0].strip()
                            cookie_value = value.split("=", 1)[1].split(";")[0].strip() if "=" in value else ""
                            cookies[name] = {
                                "value": cookie_value,
                                "raw": value,
                            }
                    log_entry(
                        url=target, status=resp.status,
                        request_headers=req_headers,
                        response_headers=dict(resp.headers),
                        duration_ms=duration_ms, module_name=self.name,
                    )
                    if cookies:
                        samples.append(cookies)
            except (urllib.error.URLError, OSError):
                continue

        return samples

    def _analyze_sessions(self, samples: list[dict], target: str) -> list[Finding]:
        findings = []

        # Identify session cookies (by name or by changing value)
        all_cookie_names = set()
        for s in samples:
            all_cookie_names.update(s.keys())

        for cookie_name in all_cookie_names:
            values = [s[cookie_name]["value"] for s in samples if cookie_name in s]
            raw_samples = [s[cookie_name]["raw"] for s in samples if cookie_name in s]

            if not values:
                continue

            is_session = (
                cookie_name.lower() in SESSION_COOKIE_NAMES
                or len(set(values)) > 1  # Value changes between requests
            )

            # Analyze cookie attributes from the raw header
            if raw_samples:
                findings.extend(self._check_cookie_attributes(cookie_name, raw_samples[0], target, is_session))

            # Entropy analysis only for session-like cookies with multiple unique values
            unique_values = list(set(values))
            if is_session and len(unique_values) >= 3:
                findings.extend(self._check_entropy(cookie_name, unique_values, target))
                findings.extend(self._check_predictability(cookie_name, unique_values, target))

        return findings

    def _check_entropy(self, cookie_name: str, values: list[str], target: str) -> list[Finding]:
        """Check Shannon entropy of session ID values."""
        findings = []

        # Calculate average entropy across all collected values
        entropies = [_shannon_entropy(v) for v in values if v]
        if not entropies:
            return findings

        avg_entropy = sum(entropies) / len(entropies)
        avg_length = sum(len(v) for v in values) / len(values)

        if avg_entropy < MIN_ENTROPY:
            findings.append(Finding(
                title=f"Low entropy in session cookie '{cookie_name}'",
                severity=Severity.HIGH,
                category=Category.AUTH,
                source=self.name,
                description=f"Session ID has low Shannon entropy ({avg_entropy:.2f} bits/char, minimum recommended: {MIN_ENTROPY}). "
                            f"Average length: {avg_length:.0f} chars. This may indicate predictable session IDs.",
                location=target,
                evidence=f"Sample values: {', '.join(v[:20] + '...' if len(v) > 20 else v for v in values[:3])}",
                remediation="Use a cryptographically secure random number generator for session IDs with at least 128 bits of entropy",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            ))

        if avg_length < 16:
            findings.append(Finding(
                title=f"Short session ID in cookie '{cookie_name}'",
                severity=Severity.MEDIUM,
                category=Category.AUTH,
                source=self.name,
                description=f"Session ID average length is {avg_length:.0f} characters. Short IDs are more susceptible to brute-force.",
                location=target,
                evidence=f"Sample: {values[0][:50]}",
                remediation="Use session IDs of at least 128 bits (typically 32+ hex characters or 22+ base64 characters)",
            ))

        return findings

    def _check_predictability(self, cookie_name: str, values: list[str], target: str) -> list[Finding]:
        """Check for sequential or predictable patterns in session IDs."""
        findings = []

        # Check if values are numeric and sequential
        try:
            numeric = [int(v) for v in values]
            numeric.sort()
            diffs = [numeric[i + 1] - numeric[i] for i in range(len(numeric) - 1)]
            if len(set(diffs)) == 1 and diffs[0] > 0:
                findings.append(Finding(
                    title=f"Sequential session IDs detected in '{cookie_name}'",
                    severity=Severity.CRITICAL,
                    category=Category.AUTH,
                    source=self.name,
                    description=f"Session IDs appear sequential (increment: {diffs[0]}). "
                                "An attacker can predict valid session IDs.",
                    location=target,
                    evidence=f"Values: {', '.join(str(n) for n in numeric[:5])}",
                    remediation="Use cryptographically random session IDs, not sequential counters",
                ))
        except (ValueError, TypeError):
            pass

        # Check if all values share a common prefix (possible weak randomness)
        if len(values) >= 3:
            prefix = _common_prefix(values)
            if prefix and len(prefix) > len(values[0]) * 0.5:
                findings.append(Finding(
                    title=f"Session IDs share long common prefix in '{cookie_name}'",
                    severity=Severity.MEDIUM,
                    category=Category.AUTH,
                    source=self.name,
                    description=f"Session IDs share a {len(prefix)}-character common prefix ({len(prefix)}/{len(values[0])} of total length). "
                                "This reduces effective entropy.",
                    location=target,
                    evidence=f"Common prefix: {prefix[:30]}",
                    remediation="Ensure the entire session ID is randomly generated, not just a suffix",
                ))

        return findings

    def _check_cookie_attributes(self, cookie_name: str, raw: str, target: str, is_session: bool) -> list[Finding]:
        """Check cookie attributes relevant to session security."""
        findings = []
        lower = raw.lower()

        # Check if session cookie is persistent (has Expires or Max-Age)
        if is_session:
            has_expires = "expires=" in lower
            has_max_age = "max-age=" in lower
            if has_expires or has_max_age:
                findings.append(Finding(
                    title=f"Session cookie '{cookie_name}' is persistent",
                    severity=Severity.MEDIUM,
                    category=Category.AUTH,
                    source=self.name,
                    description="Session cookie has Expires or Max-Age, making it persist across browser restarts. "
                                "This increases the window for session theft.",
                    location=target,
                    evidence=f"Set-Cookie: {raw[:200]}",
                    remediation="Session cookies should be transient (no Expires/Max-Age) so they are cleared when the browser closes",
                ))

        return findings

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Not used — this module doesn't wrap an external tool."""
        return []


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _common_prefix(strings: list[str]) -> str:
    """Find the longest common prefix among a list of strings."""
    if not strings:
        return ""
    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix
