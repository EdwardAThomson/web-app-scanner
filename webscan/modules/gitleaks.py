"""Gitleaks wrapper module."""

import json

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule


class GitleaksModule(BaseModule):
    name = "gitleaks"
    tool_binary = "gitleaks"
    description = "Secret detection in git repositories"
    target_type = "source"

    def get_version(self) -> str:
        try:
            result = self.run_command([self.tool_binary, "version"])
            return result.stdout.strip() or result.stderr.strip() or "unknown"
        except Exception:
            return "unknown"

    def execute(self, target: str) -> list[Finding]:
        mod_config = self.config.get("modules", {}).get("gitleaks", {})
        timeout = mod_config.get("timeout", 300)

        # For gitleaks, "target" is the repo path (from config or target arg)
        repo_path = mod_config.get("repo_path", target)

        tmp_path = self._raw_file_path("gitleaks-raw.json")

        cmd = [
            self.tool_binary,
            "detect",
            "-s", repo_path,
            "--report-format", "json",
            "-r", tmp_path,
            "--no-banner",
        ]

        # Gitleaks exits with code 1 when leaks are found — that's expected
        self.run_command(cmd, timeout=timeout)

        try:
            with open(tmp_path, "r") as f:
                raw = f.read()
        except FileNotFoundError:
            raw = "[]"

        return self.parse_output(raw)

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        if not isinstance(data, list):
            return findings

        for entry in data:
            rule_id = entry.get("RuleID", "unknown-rule")
            description = entry.get("Description", rule_id)
            file_path = entry.get("File", "")
            line = entry.get("StartLine", "")
            commit = entry.get("Commit", "")
            match = entry.get("Match", "")
            secret = entry.get("Secret", "")

            # Redact the actual secret in evidence — show first/last 3 chars
            if secret and len(secret) > 6:
                redacted = secret[:3] + "***" + secret[-3:]
            elif secret:
                redacted = "***"
            else:
                redacted = match[:50] if match else ""

            location = file_path
            if line:
                location = f"{file_path}:{line}"

            findings.append(Finding(
                title=f"[gitleaks] {description}",
                severity=Severity.HIGH,
                category=Category.SECRET,
                source=self.name,
                description=f"Potential secret detected: {description}",
                location=location,
                evidence=f"Redacted match: {redacted}",
                remediation="Rotate the exposed secret immediately, then remove it from git history using git-filter-branch or BFG Repo-Cleaner",
                metadata={
                    "rule_id": rule_id,
                    "commit": commit,
                    "author": entry.get("Author", ""),
                    "email": entry.get("Email", ""),
                    "date": entry.get("Date", ""),
                    "tags": entry.get("Tags", []),
                    "entropy": entry.get("Entropy", 0),
                },
            ))

        return findings
