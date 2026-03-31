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
import time
from datetime import datetime, timezone
from pathlib import Path

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule
from webscan.http_log import logged_request

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
    (r"(?:https?\.(?:get|request)|http\.(?:get|request)|fetch\s*\(|got\s*\(|axios\s*[\.\(]|node-fetch|urllib\.request|requests\.(?:get|post))", "Makes outbound HTTP requests"),
    (r"fs\.(?:writeFile|rename|unlink).*(?:package\.json|__dirname|__filename)", "Modifies own package files (self-modification)"),
    (r"dns\.(?:resolve|lookup)\s*\(", "Performs DNS lookups"),
    (r"os\.(?:platform|arch|type|release)\s*\(\).*(?:exec|spawn|fetch|http|require)", "Platform-conditional execution"),
    (r"net\.(?:connect|createConnection|Socket)\s*\(", "Opens raw network sockets"),
]

# Network-related patterns — specifically for lifecycle script targets
LIFECYCLE_NETWORK_PATTERNS = [
    (r"https?\.(?:get|request)|http\.(?:get|request)", "Node.js HTTP request"),
    (r"fetch\s*\(", "fetch() call"),
    (r"got\s*[\.\(]|axios\s*[\.\(]|node-fetch", "HTTP client library"),
    (r"net\.(?:connect|createConnection|Socket)\s*\(", "Raw TCP socket"),
    (r"dgram\.createSocket", "UDP socket"),
    (r"child_process.*curl|child_process.*wget", "Shell-based download"),
    (r"urllib\.request|requests\.(?:get|post)", "Python HTTP request"),
    (r"exec\s*\(\s*['\"](?:curl|wget|powershell|Invoke-WebRequest)", "Shell download command"),
]

# Minimum weekly downloads to be considered safe
MIN_DOWNLOADS = 1000

# Flag packages whose current version was published within this many hours
RECENCY_THRESHOLD_HOURS = 72

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
                pkg_raw = f.read()
                pkg_data = json.loads(pkg_raw)
        except (json.JSONDecodeError, OSError):
            return findings

        self._save_raw_output(pkg_raw, "deps-raw.json")

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

        # Check 4: Publish recency (flag very new versions)
        findings.extend(self._check_publish_recency(all_deps, str(pkg_json_path)))

        # Check 5: Suspicious code in node_modules (post-install only)
        node_modules = pkg_json_path.parent / "node_modules"
        if node_modules.is_dir():
            findings.extend(self._check_suspicious_code(all_deps, node_modules, str(pkg_json_path)))
            # Check 6: Lifecycle scripts that make network calls
            findings.extend(self._check_lifecycle_network(all_deps, node_modules, str(pkg_json_path)))

        # Check 7: Transitive dependency risks (lockfile analysis)
        lock_file = pkg_json_path.parent / "package-lock.json"
        if lock_file.is_file():
            findings.extend(self._check_transitive_deps(
                all_deps, lock_file, node_modules if node_modules.is_dir() else None,
            ))

        # Check 8: npm audit (if lock file exists)
        if lock_file.is_file():
            findings.extend(self._check_npm_audit(pkg_json_path.parent))

        # Compound severity escalation: when multiple signals converge on a package,
        # escalate to CRITICAL and add a summary finding
        findings = self._escalate_compound_signals(findings)

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

        # Batch check — limit to avoid excessive API calls
        for dep_name in list(deps.keys())[:50]:
            url = f"https://api.npmjs.org/downloads/point/last-week/{dep_name}"
            result = logged_request(url, module_name=self.name, timeout=10)
            if result is None:
                continue
            _status, body, _headers = result
            try:
                data = json.loads(body)
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
            except json.JSONDecodeError:
                continue

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

    def _check_publish_recency(self, deps: dict, location: str) -> list[Finding]:
        """Flag packages whose installed version was published very recently."""
        findings = []

        for dep_name in list(deps.keys())[:50]:
            version_spec = deps[dep_name]["version"]
            # Strip range chars to get a concrete version to look up
            concrete = re.sub(r"^[\^~>=<\s]+", "", version_spec).split(" ")[0]
            if not concrete or not re.match(r"\d+\.\d+", concrete):
                continue

            url = f"https://registry.npmjs.org/{dep_name}"
            result = logged_request(url, module_name=self.name, timeout=10)
            if result is None:
                continue
            status, body, _headers = result
            if status != 200:
                continue
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                continue

            time_map = data.get("time", {})
            publish_time_str = time_map.get(concrete)
            if not publish_time_str:
                continue

            try:
                publish_dt = datetime.fromisoformat(publish_time_str.replace("Z", "+00:00"))
                age_hours = (datetime.now(timezone.utc) - publish_dt).total_seconds() / 3600
            except (ValueError, TypeError):
                continue

            if age_hours < RECENCY_THRESHOLD_HOURS:
                age_display = f"{age_hours:.1f} hours" if age_hours >= 1 else f"{age_hours * 60:.0f} minutes"
                findings.append(Finding(
                    title=f"Very recently published: '{dep_name}@{concrete}' ({age_display} old)",
                    severity=Severity.HIGH,
                    category=Category.DEPENDENCY,
                    source=self.name,
                    description=f"Package '{dep_name}@{concrete}' was published only {age_display} ago. "
                                "Freshly published versions have not been community-vetted and are a "
                                "common vector for supply chain attacks.",
                    location=location,
                    evidence=f"Published: {publish_time_str}, Age: {age_display}",
                    remediation=f"Pin to the previous version of '{dep_name}' until this release has "
                                "been vetted. Check the package changelog and maintainer activity.",
                    metadata={
                        "package": dep_name,
                        "version": concrete,
                        "published": publish_time_str,
                        "age_hours": round(age_hours, 1),
                    },
                ))

        return findings

    def _check_lifecycle_network(self, deps: dict, node_modules: Path, location: str) -> list[Finding]:
        """Inspect the actual files executed by lifecycle scripts for network activity."""
        findings = []
        compiled = [(re.compile(p), desc) for p, desc in LIFECYCLE_NETWORK_PATTERNS]

        all_pkgs = list(deps.keys())
        # Also check scoped packages
        for dep_name in all_pkgs:
            pkg_dir = node_modules / dep_name
            dep_pkg = pkg_dir / "package.json"
            if not dep_pkg.is_file():
                continue

            try:
                with open(dep_pkg) as f:
                    dep_data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            dep_scripts = dep_data.get("scripts", {})
            for script_name in LIFECYCLE_SCRIPTS:
                if script_name not in dep_scripts:
                    continue

                script_cmd = dep_scripts[script_name]
                # Extract the target file from the script command
                # Common forms: "node setup.js", "node scripts/postinstall.js", "./install.sh"
                target_files = self._extract_script_targets(script_cmd, pkg_dir)

                for target_path in target_files:
                    if not target_path.is_file():
                        continue
                    try:
                        content = target_path.read_text(errors="ignore")
                    except OSError:
                        continue

                    matched_patterns = []
                    for pattern, desc in compiled:
                        if pattern.search(content):
                            matched_patterns.append(desc)

                    if matched_patterns:
                        rel_path = target_path.relative_to(node_modules)
                        findings.append(Finding(
                            title=f"Lifecycle script in '{dep_name}' makes network calls",
                            severity=Severity.CRITICAL,
                            category=Category.DEPENDENCY,
                            source=self.name,
                            description=f"Package '{dep_name}' has a '{script_name}' script that executes "
                                        f"'{script_cmd}'. The target file contains network activity: "
                                        f"{', '.join(matched_patterns)}. "
                                        "This is a strong indicator of supply chain compromise.",
                            location=str(rel_path),
                            evidence=f"Script: \"{script_name}\": \"{script_cmd}\"\n"
                                     f"Network patterns: {', '.join(matched_patterns)}",
                            remediation=f"Inspect {rel_path} immediately. If unexpected, remove '{dep_name}' "
                                        "and run with --ignore-scripts. Check if this is a known-malicious package.",
                            metadata={
                                "package": dep_name,
                                "script": script_name,
                                "script_cmd": script_cmd,
                                "network_patterns": matched_patterns,
                                "target_file": str(rel_path),
                            },
                        ))

        return findings

    def _extract_script_targets(self, script_cmd: str, pkg_dir: Path) -> list[Path]:
        """Extract file paths referenced in a lifecycle script command."""
        targets = []

        # Handle "node ." which means run the package's main/index.js
        if re.search(r"\bnode\s+\.\s*$", script_cmd.strip()) or "node" == script_cmd.strip():
            targets.append(pkg_dir / "index.js")
            return targets

        # Match: node <file>, python <file>, sh <file>, ./<file>
        patterns = [
            r"(?:node|python3?|sh|bash)\s+([^\s;&|]+)",
            r"\./([^\s;&|]+)",
        ]
        for pat in patterns:
            for match in re.finditer(pat, script_cmd):
                fpath = pkg_dir / match.group(1)
                targets.append(fpath)

        return targets

    def _check_transitive_deps(self, direct_deps: dict, lock_file: Path,
                               node_modules: Path | None) -> list[Finding]:
        """Parse package-lock.json for transitive deps not in package.json and scan them."""
        findings = []

        try:
            with open(lock_file) as f:
                lock_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return findings

        direct_names = set(direct_deps.keys())

        # lockfileVersion 2/3 uses "packages" with "node_modules/..." keys
        packages = lock_data.get("packages", {})
        transitive_with_scripts = []

        for pkg_path, pkg_info in packages.items():
            if not pkg_path.startswith("node_modules/"):
                continue
            # Extract package name from path (handles scoped packages)
            pkg_name = pkg_path.removeprefix("node_modules/")
            # Skip nested node_modules (transitive of transitive)
            if "node_modules/" in pkg_name:
                continue
            if pkg_name in direct_names:
                continue

            # Check if this transitive dep has lifecycle scripts
            has_install = pkg_info.get("hasInstallScript", False)
            if has_install:
                version = pkg_info.get("version", "?")
                transitive_with_scripts.append((pkg_name, version))

                findings.append(Finding(
                    title=f"Transitive dependency '{pkg_name}' has install scripts",
                    severity=Severity.HIGH,
                    category=Category.DEPENDENCY,
                    source=self.name,
                    description=f"'{pkg_name}@{version}' is a transitive dependency (not in your "
                                "package.json) that has lifecycle install scripts. You did not "
                                "explicitly choose this package — it was pulled in by another dependency. "
                                "Transitive deps with install scripts are a prime supply chain attack vector.",
                    location=str(lock_file),
                    evidence=f"Package: {pkg_name}@{version}, hasInstallScript: true",
                    remediation=f"Identify which direct dependency pulls in '{pkg_name}' (npm ls {pkg_name}). "
                                "If unexpected, investigate the package on npmjs.com and consider overriding "
                                "or removing it.",
                    metadata={
                        "package": pkg_name,
                        "version": version,
                        "transitive": True,
                        "has_install_script": True,
                    },
                ))

        # Check recency and popularity for flagged transitive deps
        for pkg_name, version in transitive_with_scripts:
            transitive_dep = {pkg_name: {"version": version, "type": "transitive"}}
            findings.extend(self._check_publish_recency(transitive_dep, str(lock_file)))
            findings.extend(self._check_popularity(transitive_dep, str(lock_file)))

        # If node_modules exists, scan transitive deps with scripts for network activity
        if node_modules and transitive_with_scripts:
            compiled = [(re.compile(p), desc) for p, desc in LIFECYCLE_NETWORK_PATTERNS]
            for pkg_name, version in transitive_with_scripts:
                pkg_dir = node_modules / pkg_name
                dep_pkg = pkg_dir / "package.json"
                if not dep_pkg.is_file():
                    continue

                try:
                    with open(dep_pkg) as f:
                        dep_data = json.load(f)
                except (json.JSONDecodeError, OSError):
                    continue

                dep_scripts = dep_data.get("scripts", {})
                for script_name in LIFECYCLE_SCRIPTS:
                    if script_name not in dep_scripts:
                        continue
                    script_cmd = dep_scripts[script_name]
                    target_files = self._extract_script_targets(script_cmd, pkg_dir)

                    for target_path in target_files:
                        if not target_path.is_file():
                            continue
                        try:
                            content = target_path.read_text(errors="ignore")
                        except OSError:
                            continue

                        matched = []
                        for pattern, desc in compiled:
                            if pattern.search(content):
                                matched.append(desc)

                        if matched:
                            rel_path = target_path.relative_to(node_modules)
                            findings.append(Finding(
                                title=f"CRITICAL: Transitive dep '{pkg_name}' install script makes network calls",
                                severity=Severity.CRITICAL,
                                category=Category.DEPENDENCY,
                                source=self.name,
                                description=f"Transitive dependency '{pkg_name}@{version}' has a "
                                            f"'{script_name}' script ('{script_cmd}') that makes network "
                                            f"calls: {', '.join(matched)}. This package is NOT in your "
                                            "package.json — it was injected via another dependency. "
                                            "This is a strong indicator of supply chain compromise "
                                            "(similar to the axios/plain-crypto-js attack pattern).",
                                location=str(rel_path),
                                evidence=f"Script: \"{script_name}\": \"{script_cmd}\"\n"
                                         f"Network patterns: {', '.join(matched)}",
                                remediation=f"URGENT: Remove or override '{pkg_name}' immediately. "
                                            f"Run: npm ls {pkg_name} to find which dependency pulls it in. "
                                            "Check your system for compromise artifacts. Rotate credentials.",
                                metadata={
                                    "package": pkg_name,
                                    "version": version,
                                    "transitive": True,
                                    "script": script_name,
                                    "network_patterns": matched,
                                },
                            ))

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

    def _escalate_compound_signals(self, findings: list[Finding]) -> list[Finding]:
        """Escalate severity when multiple risk signals converge on the same package."""
        # Collect signals per package
        signals: dict[str, list[str]] = {}
        for f in findings:
            pkg = (f.metadata or {}).get("package")
            if not pkg:
                continue
            signals.setdefault(pkg, [])
            title_lower = f.title.lower()
            if "recently published" in title_lower:
                signals[pkg].append("recent_publish")
            if "lifecycle" in title_lower or "install script" in title_lower:
                signals[pkg].append("lifecycle_script")
            if "network" in title_lower:
                signals[pkg].append("network_call")
            if "transitive" in title_lower:
                signals[pkg].append("transitive")
            if "typosquat" in title_lower:
                signals[pkg].append("typosquat")
            if "low-popularity" in title_lower:
                signals[pkg].append("low_popularity")

        # Identify packages with converging signals (2+ distinct risk types)
        ESCALATION_COMBOS = [
            ({"recent_publish", "lifecycle_script"}, "recently published with lifecycle scripts"),
            ({"recent_publish", "network_call"}, "recently published with network activity"),
            ({"transitive", "network_call"}, "transitive dependency with network activity"),
            ({"typosquat", "lifecycle_script"}, "possible typosquat with lifecycle scripts"),
            ({"low_popularity", "network_call"}, "low-popularity package with network activity"),
        ]

        for pkg, pkg_signals in signals.items():
            signal_set = set(pkg_signals)
            if len(signal_set) < 2:
                continue

            matched_combos = []
            for combo, desc in ESCALATION_COMBOS:
                if combo.issubset(signal_set):
                    matched_combos.append(desc)

            if matched_combos:
                # Escalate all existing findings for this package to at least HIGH
                for f in findings:
                    if (f.metadata or {}).get("package") == pkg and f.severity.value > Severity.HIGH.value:
                        f.severity = Severity.HIGH

                findings.append(Finding(
                    title=f"Compound supply chain risk: '{pkg}' ({len(signal_set)} signals)",
                    severity=Severity.CRITICAL,
                    category=Category.DEPENDENCY,
                    source=self.name,
                    description=f"Package '{pkg}' triggered multiple independent risk signals: "
                                f"{', '.join(matched_combos)}. "
                                "The combination of these signals is a strong indicator of a "
                                "supply chain attack (e.g., the axios/plain-crypto-js pattern).",
                    location=pkg,
                    evidence=f"Signals: {', '.join(sorted(signal_set))}",
                    remediation=f"URGENT: Investigate '{pkg}' immediately. Run: npm ls {pkg} to trace "
                                "how it entered your dependency tree. Check npmjs.com for the package "
                                "and its maintainer. If suspicious, remove it and rotate all credentials.",
                    metadata={
                        "package": pkg,
                        "signal_count": len(signal_set),
                        "signals": sorted(signal_set),
                        "matched_combos": matched_combos,
                    },
                ))

        return findings

    def parse_output(self, raw_output: str) -> list[Finding]:
        """Not used — this module doesn't wrap an external tool."""
        return []
