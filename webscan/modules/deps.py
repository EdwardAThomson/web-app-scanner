"""Supply chain / dependency audit module (pure Python).

Audits npm project dependencies for supply chain risks:
- Typosquat detection (edit distance against popular packages)
- Lifecycle scripts (preinstall/postinstall hooks)
- Package popularity (low download counts)
- Suspicious code patterns in installed packages
- npm audit integration (known vulnerabilities)

Works both pre-install (package.json only) and post-install (+ node_modules).
"""

import json
import os
import re
import subprocess
import urllib.request
import urllib.error
import ssl
from pathlib import Path

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule

# Top npm packages by downloads — used for typosquat comparison
# This is a representative subset; a production version would use a larger list
POPULAR_PACKAGES = {
    "express", "react", "react-dom", "lodash", "axios", "moment", "chalk",
    "commander", "debug", "dotenv", "uuid", "inquirer", "glob", "minimist",
    "yargs", "fs-extra", "body-parser", "cors", "webpack", "babel-core",
    "typescript", "eslint", "prettier", "jest", "mocha", "chai", "sinon",
    "underscore", "async", "bluebird", "request", "node-fetch", "got",
    "cheerio", "puppeteer", "mongoose", "sequelize", "knex", "pg",
    "mysql2", "redis", "ioredis", "socket.io", "jsonwebtoken", "bcrypt",
    "bcryptjs", "passport", "helmet", "morgan", "winston", "pino",
    "bunyan", "nodemon", "pm2", "next", "nuxt", "vue", "angular",
    "svelte", "tailwindcss", "bootstrap", "jquery", "d3", "three",
    "rxjs", "ramda", "immutable", "mobx", "redux", "zustand",
    "prisma", "drizzle-orm", "zod", "yup", "joi", "ajv",
    "sharp", "multer", "formidable", "busboy", "cookie-parser",
    "express-session", "connect-redis", "compression", "serve-static",
    "http-proxy-middleware", "concurrently", "cross-env", "rimraf",
    "mkdirp", "semver", "tar", "archiver", "xml2js", "fast-xml-parser",
    "marked", "highlight.js", "prismjs", "dayjs", "date-fns", "luxon",
    "nanoid", "cuid", "short-uuid", "colors", "picocolors", "kleur",
    "ora", "listr2", "progress", "cli-progress", "table", "boxen",
    "figlet", "open", "execa", "shelljs", "cross-spawn",
    "dotenv-expand", "config", "convict", "nconf",
    "supertest", "nock", "msw", "playwright", "cypress",
    "esbuild", "rollup", "vite", "parcel", "turbo", "lerna", "nx",
    "pnpm", "yarn", "npm", "bignumber.js", "big.js", "decimal.js",
    "crypto-js", "tweetnacl", "libsodium", "argon2",
}

# Suspicious patterns in package source code
SUSPICIOUS_PATTERNS = [
    (r"os\.homedir\(\)", "Accesses user home directory"),
    (r"readFile.*\.env", "Reads .env file"),
    (r"readFile.*\.ssh", "Reads SSH directory"),
    (r"readFile.*authorized_keys", "Reads authorized_keys"),
    (r"child_process", "Uses child_process (command execution)"),
    (r"eval\s*\(", "Uses eval()"),
    (r"new\s+Function\s*\(", "Dynamically creates functions"),
    (r"https?://[^\s'\"]+\.(?:xyz|tk|ml|ga|cf|gq|top)\b", "Connects to suspicious TLD"),
    (r"atob\s*\(|Buffer\.from\s*\([^)]+,\s*['\"]base64", "Decodes base64 data"),
    (r"ssh-rsa\s+AAAA", "Contains SSH public key"),
    (r"process\.env\b", "Accesses environment variables"),
]

# Minimum weekly downloads to be considered safe
MIN_DOWNLOADS = 1000

# Lifecycle scripts that run automatically
LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "preuninstall", "postuninstall"]


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        curr_row = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row
    return prev_row[-1]


class DepsModule(BaseModule):
    name = "deps"
    tool_binary = ""
    description = "Supply chain / dependency audit (typosquats, lifecycle scripts, popularity)"
    target_type = "source"

    def check_installed(self) -> tuple[bool, str]:
        return True, "built-in"

    def get_version(self) -> str:
        return "built-in"

    def execute(self, target: str) -> list[Finding]:
        findings = []
        project_dir = Path(target)

        # Check for package.json
        pkg_json_path = project_dir / "package.json"
        if not pkg_json_path.is_file():
            # Try common subdirectories
            for sub in [".", "frontend", "client", "app"]:
                candidate = project_dir / sub / "package.json"
                if candidate.is_file():
                    pkg_json_path = candidate
                    break
            else:
                return findings  # No npm project found

        try:
            with open(pkg_json_path) as f:
                pkg_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return findings

        # Collect all dependency names
        all_deps = {}
        for dep_type in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            deps = pkg_data.get(dep_type, {})
            for name, version in deps.items():
                all_deps[name] = {"version": version, "type": dep_type}

        if not all_deps:
            return findings

        # Check 1: Typosquats
        findings.extend(self._check_typosquats(all_deps, str(pkg_json_path)))

        # Check 2: Lifecycle scripts
        findings.extend(self._check_lifecycle_scripts(pkg_data, str(pkg_json_path)))

        # Check 3: Package popularity (query npm registry)
        findings.extend(self._check_popularity(all_deps, str(pkg_json_path)))

        # Check 4: Suspicious code in node_modules (post-install only)
        node_modules = pkg_json_path.parent / "node_modules"
        if node_modules.is_dir():
            findings.extend(self._check_suspicious_code(all_deps, node_modules, str(pkg_json_path)))

        # Check 5: npm audit (if lock file exists)
        lock_file = pkg_json_path.parent / "package-lock.json"
        if lock_file.is_file():
            findings.extend(self._check_npm_audit(pkg_json_path.parent))

        return findings

    def _check_typosquats(self, deps: dict, location: str) -> list[Finding]:
        """Check if any dependency name is suspiciously close to a popular package."""
        findings = []

        for dep_name in deps:
            if dep_name in POPULAR_PACKAGES:
                continue  # Exact match, it IS the popular package

            # Check edit distance against all popular packages
            for popular in POPULAR_PACKAGES:
                dist = _edit_distance(dep_name.lower(), popular.lower())
                # Flag if edit distance is 1-2 (very similar but not identical)
                if 0 < dist <= 2 and len(dep_name) > 3:
                    findings.append(Finding(
                        title=f"Possible typosquat: '{dep_name}' is similar to '{popular}'",
                        severity=Severity.HIGH,
                        category=Category.DEPENDENCY,
                        source=self.name,
                        description=f"Package '{dep_name}' has an edit distance of {dist} from popular package '{popular}'. "
                                    "This could be a typosquat attack.",
                        location=location,
                        evidence=f"{dep_name} (installed) vs {popular} (popular, distance={dist})",
                        remediation=f"Verify that '{dep_name}' is the correct package. If you intended '{popular}', replace it.",
                        metadata={
                            "package": dep_name,
                            "similar_to": popular,
                            "edit_distance": dist,
                        },
                    ))
                    break  # Only report the closest match

        return findings

    def _check_lifecycle_scripts(self, pkg_data: dict, location: str) -> list[Finding]:
        """Check for preinstall/postinstall scripts in package.json."""
        findings = []
        scripts = pkg_data.get("scripts", {})

        for script_name in LIFECYCLE_SCRIPTS:
            if script_name in scripts:
                script_cmd = scripts[script_name]
                findings.append(Finding(
                    title=f"Lifecycle script detected: {script_name}",
                    severity=Severity.MEDIUM,
                    category=Category.DEPENDENCY,
                    source=self.name,
                    description=f"package.json has a '{script_name}' script that runs automatically: {script_cmd}",
                    location=location,
                    evidence=f'"{script_name}": "{script_cmd}"',
                    remediation=f"Review the '{script_name}' script to ensure it is safe. "
                                "Use --ignore-scripts flag with npm install if unsure.",
                ))

        # Also check dependencies' package.json files in node_modules
        return findings

    def _check_popularity(self, deps: dict, location: str) -> list[Finding]:
        """Query npm registry for download counts and flag low-popularity packages."""
        findings = []
        ctx = ssl.create_default_context()

        # Batch check — limit to avoid excessive API calls
        for dep_name in list(deps.keys())[:50]:
            try:
                url = f"https://api.npmjs.org/downloads/point/last-week/{dep_name}"
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "webscan/0.1.0")
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    data = json.loads(resp.read().decode())
                    downloads = data.get("downloads", 0)

                    if downloads < MIN_DOWNLOADS:
                        findings.append(Finding(
                            title=f"Low-popularity package: '{dep_name}' ({downloads} weekly downloads)",
                            severity=Severity.MEDIUM,
                            category=Category.DEPENDENCY,
                            source=self.name,
                            description=f"Package '{dep_name}' has only {downloads} weekly downloads. "
                                        "Low-popularity packages are higher risk for supply chain attacks.",
                            location=location,
                            evidence=f"{dep_name}: {downloads} downloads/week",
                            remediation=f"Inspect the source code of '{dep_name}' manually before trusting it. "
                                        "Consider if a more established alternative exists.",
                            metadata={
                                "package": dep_name,
                                "weekly_downloads": downloads,
                            },
                        ))
            except (urllib.error.URLError, OSError, json.JSONDecodeError):
                continue  # Registry unavailable, skip

        return findings

    def _check_suspicious_code(self, deps: dict, node_modules: Path, location: str) -> list[Finding]:
        """Scan installed packages for suspicious code patterns."""
        findings = []
        compiled_patterns = [(re.compile(p), desc) for p, desc in SUSPICIOUS_PATTERNS]

        for dep_name in deps:
            pkg_dir = node_modules / dep_name
            if not pkg_dir.is_dir():
                continue

            # Check the package's own package.json for lifecycle scripts
            dep_pkg = pkg_dir / "package.json"
            if dep_pkg.is_file():
                try:
                    with open(dep_pkg) as f:
                        dep_data = json.load(f)
                    dep_scripts = dep_data.get("scripts", {})
                    for script_name in LIFECYCLE_SCRIPTS:
                        if script_name in dep_scripts:
                            findings.append(Finding(
                                title=f"Dependency '{dep_name}' has {script_name} script",
                                severity=Severity.HIGH,
                                category=Category.DEPENDENCY,
                                source=self.name,
                                description=f"Installed package '{dep_name}' has a '{script_name}' lifecycle script: "
                                            f"{dep_scripts[script_name]}",
                                location=str(dep_pkg),
                                evidence=f'"{script_name}": "{dep_scripts[script_name]}"',
                                remediation=f"Review '{dep_name}' lifecycle script. Malicious packages often use "
                                            "postinstall scripts to exfiltrate data.",
                            ))
                except (json.JSONDecodeError, OSError):
                    pass

            # Scan JS files for suspicious patterns (limit file count per package)
            js_files = list(pkg_dir.glob("**/*.js"))[:20]
            for js_file in js_files:
                try:
                    content = js_file.read_text(errors="ignore")
                except OSError:
                    continue

                for pattern, description in compiled_patterns:
                    matches = pattern.findall(content)
                    if matches:
                        rel_path = js_file.relative_to(node_modules)
                        findings.append(Finding(
                            title=f"Suspicious pattern in '{dep_name}': {description}",
                            severity=Severity.MEDIUM,
                            category=Category.DEPENDENCY,
                            source=self.name,
                            description=f"Package '{dep_name}' contains code that {description.lower()}",
                            location=str(rel_path),
                            evidence=f"Pattern: {pattern.pattern}, Matches: {len(matches)}",
                            remediation=f"Inspect {rel_path} manually to determine if this is malicious or legitimate",
                            metadata={
                                "package": dep_name,
                                "pattern": description,
                                "file": str(rel_path),
                            },
                        ))
                        break  # One finding per pattern per package

        return findings

    def _check_npm_audit(self, project_dir: Path) -> list[Finding]:
        """Run npm audit and parse results."""
        findings = []

        try:
            result = subprocess.run(
                ["npm", "audit", "--json", "--package-lock-only"],
                capture_output=True, text=True, timeout=60,
                cwd=str(project_dir),
            )
            data = json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, OSError):
            return findings

        # npm audit JSON format
        vulnerabilities = data.get("vulnerabilities", {})
        for pkg_name, vuln_info in vulnerabilities.items():
            severity = vuln_info.get("severity", "info")
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "moderate": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            via = vuln_info.get("via", [])
            # "via" can be strings (transitive) or dicts (direct)
            advisories = [v for v in via if isinstance(v, dict)]

            if advisories:
                for adv in advisories:
                    findings.append(Finding(
                        title=f"npm audit: {adv.get('title', pkg_name)} ({severity})",
                        severity=sev_map.get(severity, Severity.INFO),
                        category=Category.DEPENDENCY,
                        source=self.name,
                        description=adv.get("title", f"Vulnerability in {pkg_name}"),
                        location=f"{pkg_name}@{vuln_info.get('range', '?')}",
                        evidence=f"Severity: {severity}, Range: {vuln_info.get('range', '?')}",
                        remediation=f"Fix available: {vuln_info.get('fixAvailable', 'unknown')}",
                        reference=adv.get("url", ""),
                        metadata={
                            "package": pkg_name,
                            "npm_severity": severity,
                            "cwe": adv.get("cwe", []),
                        },
                    ))

        return findings

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Not used — this module doesn't wrap an external tool."""
        return []
