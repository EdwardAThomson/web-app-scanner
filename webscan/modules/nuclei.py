"""Nuclei wrapper module."""

import json

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

TYPE_TO_CATEGORY = {
    "ssl": Category.TLS,
    "dns": Category.MISCONFIGURATION,
    "http": Category.VULNERABILITY,
    "file": Category.CODE,
    "network": Category.VULNERABILITY,
}


class NucleiModule(BaseModule):
    name = "nuclei"
    tool_binary = "nuclei"
    description = "Templated vulnerability scanning (CVEs, misconfigs, exposures)"

    def get_version(self) -> str:
        try:
            result = self.run_command([self.tool_binary, "--version"])
            output = result.stderr + result.stdout
            for line in output.splitlines():
                if "nuclei" in line.lower():
                    return self.strip_ansi(line.strip())
            return self.strip_ansi(output.strip().splitlines()[0]) if output.strip() else "unknown"
        except Exception:
            return "unknown"

    def execute(self, target: str) -> list[Finding]:
        mod_config = self.config.get("modules", {}).get("nuclei", {})
        timeout = mod_config.get("timeout", 600)

        cmd = [
            self.tool_binary,
            "-u", target,
            "-j",  # JSONL output to stdout
            "-silent",
        ]

        # Add template filters
        templates = mod_config.get("templates", [])
        for t in templates:
            cmd.extend(["-t", t])

        severity_filter = mod_config.get("severity", "")
        if severity_filter:
            cmd.extend(["-severity", severity_filter])

        result = self.run_command(cmd, timeout=timeout)
        return self.parse_output(result.stdout)

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        for line in raw_output.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            severity_str = info.get("severity", "info").lower()
            severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

            template_id = entry.get("template-id", entry.get("templateID", ""))
            template_name = info.get("name", template_id)
            matched_at = entry.get("matched-at", entry.get("matched", ""))
            entry_type = entry.get("type", "http").lower()

            category = TYPE_TO_CATEGORY.get(entry_type, Category.VULNERABILITY)

            # Build reference from CVE/CWE/references
            refs = info.get("reference", [])
            if isinstance(refs, list):
                ref_str = ", ".join(refs[:3])
            else:
                ref_str = str(refs)

            classification = info.get("classification", {})
            cve_id = classification.get("cve-id", "")
            if isinstance(cve_id, list):
                cve_id = ", ".join(cve_id)

            findings.append(Finding(
                title=f"[nuclei] {template_name}",
                severity=severity,
                category=category,
                source=self.name,
                description=info.get("description", template_name),
                location=matched_at,
                evidence=entry.get("extracted-results", entry.get("matcher-name", "")),
                remediation=info.get("remediation", ""),
                reference=cve_id or ref_str,
                metadata={
                    "template_id": template_id,
                    "tags": info.get("tags", []),
                    "matcher_name": entry.get("matcher-name", ""),
                    "curl_command": entry.get("curl-command", ""),
                },
            ))

        return findings
