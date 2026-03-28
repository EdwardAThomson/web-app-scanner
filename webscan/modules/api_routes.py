"""API route discovery and testing module (pure Python).

Parses source code to extract route definitions from Express.js and FastAPI
applications, then optionally tests discovered endpoints for common issues
like unauthenticated access.
"""

import os
import re
import urllib.request
import urllib.error
import ssl

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule

# Route patterns for common frameworks
EXPRESS_PATTERNS = [
    # app.get('/path', ...) or router.post('/path', ...)
    re.compile(
        r"""(?:app|router)\.(get|post|put|patch|delete|all|options)\s*\(\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    ),
    # express.Router() route chaining: .route('/path').get(...)
    re.compile(
        r"""\.route\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.(get|post|put|patch|delete)""",
        re.IGNORECASE,
    ),
]

FASTAPI_PATTERNS = [
    # @app.get("/path") or @router.post("/path")
    re.compile(
        r"""@(?:app|router)\.(get|post|put|patch|delete|options)\s*\(\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    ),
]

# File extensions to scan per framework
FRAMEWORK_FILES = {
    "express": ("*.js", "*.ts", "*.mjs"),
    "fastapi": ("*.py",),
}


class ApiRoutesModule(BaseModule):
    name = "api_routes"
    tool_binary = ""
    description = "API route discovery and auth testing"
    target_type = "both"

    def check_installed(self) -> tuple[bool, str]:
        return True, "built-in"

    def get_version(self) -> str:
        return "built-in"

    def execute(self, target: str) -> list[Finding]:
        source_path = self.config.get("source_path", "")
        target_url = self.config.get("target", "")

        findings = []

        # Phase 1: Discover routes from source code
        if source_path and os.path.isdir(source_path):
            routes = self._discover_routes(source_path)
            if not routes:
                return findings

            # Report discovered routes as INFO findings
            for method, path, file_loc, framework in routes:
                findings.append(Finding(
                    title=f"[api_routes] {method.upper()} {path}",
                    severity=Severity.INFO,
                    category=Category.AUTH,
                    source=self.name,
                    description=f"API route discovered: {method.upper()} {path} ({framework})",
                    location=file_loc,
                    metadata={
                        "method": method.upper(),
                        "path": path,
                        "framework": framework,
                    },
                ))

            # Phase 2: Test routes if we have a target URL
            if target_url:
                findings.extend(self._test_routes(target_url, routes))

        return findings

    def _discover_routes(self, source_path: str) -> list[tuple[str, str, str, str]]:
        """Walk source files and extract route definitions.

        Returns list of (method, path, file:line, framework).
        """
        routes = []

        for dirpath, _dirnames, filenames in os.walk(source_path):
            # Skip node_modules, .git, __pycache__, venv directories
            rel = os.path.relpath(dirpath, source_path)
            if any(skip in rel.split(os.sep) for skip in
                   ["node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build"]):
                continue

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(filepath, source_path)

                # Check Express patterns for JS/TS files
                if filename.endswith((".js", ".ts", ".mjs")):
                    routes.extend(
                        self._scan_file(filepath, rel_path, EXPRESS_PATTERNS, "express")
                    )

                # Check FastAPI patterns for Python files
                if filename.endswith(".py"):
                    routes.extend(
                        self._scan_file(filepath, rel_path, FASTAPI_PATTERNS, "fastapi")
                    )

        return routes

    def _scan_file(
        self, filepath: str, rel_path: str, patterns: list, framework: str
    ) -> list[tuple[str, str, str, str]]:
        """Scan a single file for route patterns."""
        routes = []
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
        except OSError:
            return routes

        for pattern in patterns:
            for match in pattern.finditer(content):
                groups = match.groups()
                if framework == "express" and ".route(" in match.group():
                    # .route('/path').get(...) — groups are (path, method)
                    path, method = groups[0], groups[1]
                else:
                    # Standard: (method, path)
                    method, path = groups[0], groups[1]

                # Find line number
                line_num = content[:match.start()].count("\n") + 1
                location = f"{rel_path}:{line_num}"

                routes.append((method, path, location, framework))

        return routes

    def _test_routes(
        self, base_url: str, routes: list[tuple[str, str, str, str]]
    ) -> list[Finding]:
        """Test discovered routes for unauthenticated access."""
        findings = []
        base_url = base_url.rstrip("/")
        ctx = ssl.create_default_context()
        tested = set()

        for method, path, file_loc, framework in routes:
            # Only test unique method+path combinations
            key = (method.upper(), path)
            if key in tested:
                continue
            tested.add(key)

            # Only test GET endpoints for now (safe, no side effects)
            if method.upper() != "GET":
                continue

            # Skip parameterized routes — we can't guess the values
            if ":" in path or "{" in path or "<" in path:
                continue

            url = base_url + path
            try:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "webscan/0.1.0")
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    status = resp.status
                    if status == 200:
                        findings.append(Finding(
                            title=f"[api_routes] Unauthenticated access: GET {path}",
                            severity=Severity.MEDIUM,
                            category=Category.AUTH,
                            source=self.name,
                            description=f"GET {path} returned 200 without authentication. Verify this endpoint should be public.",
                            location=url,
                            evidence=f"Status: {status}",
                            remediation="Add authentication middleware if this endpoint should be protected",
                            metadata={
                                "method": "GET",
                                "path": path,
                                "status": status,
                                "defined_in": file_loc,
                            },
                        ))
            except urllib.error.HTTPError as e:
                # 401/403 is expected for protected routes — that's good
                if e.code in (401, 403):
                    pass  # Properly protected
                # 404/405 might mean the route isn't deployed at this URL
            except (urllib.error.URLError, OSError):
                pass  # Network error, skip

        return findings

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Not used — this module doesn't wrap an external tool."""
        return []
