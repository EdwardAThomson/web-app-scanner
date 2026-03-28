"""testssl.sh wrapper module."""

import json

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "OK": Severity.INFO,
    "WARN": Severity.MEDIUM,
}


class TestSSLModule(BaseModule):
    name = "testssl"
    tool_binary = "testssl.sh"
    description = "TLS/SSL configuration and vulnerability testing"

    def get_version(self) -> str:
        try:
            result = self.run_command([self.tool_binary, "--version"])
            # testssl.sh prints version info to stderr
            for line in (result.stderr + result.stdout).splitlines():
                if "testssl" in line.lower() and ("." in line):
                    return self.strip_ansi(line.strip())
            return "unknown"
        except Exception:
            return "unknown"

    def execute(self, target: str) -> list[Finding]:
        timeout = self.config.get("modules", {}).get("testssl", {}).get("timeout", 600)
        tmp_path = self._raw_file_path("testssl-raw.json")

        cmd = [
            self.tool_binary,
            "--jsonfile", tmp_path,
            "--warnings", "off",
            "--color", "0",
            target,
        ]
        self.run_command(cmd, timeout=timeout)

        with open(tmp_path, "r") as f:
            raw = f.read()

        return self.parse_output(raw)

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        # testssl.sh JSON is a flat list of objects
        entries = data if isinstance(data, list) else data.get("scanResult", [])

        # If scanResult contains nested host results, flatten
        if entries and isinstance(entries[0], dict) and "serverDefaults" in entries[0]:
            flat = []
            for host_result in entries:
                for section in ["protocols", "ciphers", "serverDefaults",
                                "headerResponse", "vulnerabilities", "fs"]:
                    flat.extend(host_result.get(section, []))
            entries = flat

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            severity_str = entry.get("severity", "INFO").upper()
            severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

            # Skip OK/INFO entries unless they indicate a problem
            if severity == Severity.INFO and severity_str in ("OK", "INFO"):
                continue

            finding_text = entry.get("finding", "")
            entry_id = entry.get("id", "")

            findings.append(Finding(
                title=f"[testssl] {entry_id}: {finding_text[:100]}",
                severity=severity,
                category=Category.TLS,
                source=self.name,
                description=finding_text,
                location=entry.get("ip", "") + "/" + entry.get("port", "443"),
                evidence=finding_text,
                reference=entry.get("cve", ""),
                metadata={
                    "id": entry_id,
                    "cwe": entry.get("cwe", ""),
                },
            ))

        return findings
