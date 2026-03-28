"""Semgrep wrapper module."""

import json

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule

SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Map semgrep metadata categories to our categories
CATEGORY_MAP = {
    "security": Category.VULNERABILITY,
    "correctness": Category.CODE,
    "best-practice": Category.CODE,
    "performance": Category.CODE,
}


class SemgrepModule(BaseModule):
    name = "semgrep"
    tool_binary = "semgrep"
    description = "Multi-language static analysis (SAST)"
    target_type = "source"

    def get_version(self) -> str:
        try:
            result = self.run_command([self.tool_binary, "--version"])
            return self.strip_ansi(result.stdout.strip())
        except Exception:
            return "unknown"

    def execute(self, target: str) -> list[Finding]:
        mod_config = self.config.get("modules", {}).get("semgrep", {})
        timeout = mod_config.get("timeout", 600)
        config = mod_config.get("config", "auto")

        cmd = [
            self.tool_binary,
            "scan",
            "--json",
            "--config", config,
            target,
        ]

        result = self.run_command(cmd, timeout=timeout)
        self._save_raw_output(result.stdout, "semgrep-raw.json")
        return self.parse_output(result.stdout)

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        results = data.get("results", [])
        for entry in results:
            check_id = entry.get("check_id", "")
            path = entry.get("path", "")
            start = entry.get("start", {})
            line = start.get("line", "")
            message = entry.get("extra", {}).get("message", "")
            severity_str = entry.get("extra", {}).get("severity", "WARNING")
            severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            # Try to determine category from metadata
            metadata = entry.get("extra", {}).get("metadata", {})
            category_str = metadata.get("category", "security")
            category = CATEGORY_MAP.get(category_str, Category.CODE)

            # Semgrep security findings should map to VULNERABILITY
            if "security" in check_id.lower() or metadata.get("cwe", []):
                category = Category.VULNERABILITY

            location = f"{path}:{line}" if line else path
            snippet = entry.get("extra", {}).get("lines", "")

            cwe_list = metadata.get("cwe", [])
            if isinstance(cwe_list, list):
                cwe_ref = ", ".join(cwe_list[:3])
            else:
                cwe_ref = str(cwe_list)

            findings.append(Finding(
                title=f"[semgrep] {check_id}",
                severity=severity,
                category=category,
                source=self.name,
                description=message,
                location=location,
                evidence=snippet[:500] if snippet else "",
                remediation=metadata.get("fix", ""),
                reference=cwe_ref or metadata.get("references", ""),
                metadata={
                    "check_id": check_id,
                    "owasp": metadata.get("owasp", []),
                    "confidence": metadata.get("confidence", ""),
                    "technology": metadata.get("technology", []),
                },
            ))

        return findings
