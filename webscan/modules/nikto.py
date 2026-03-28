"""Nikto wrapper module."""

import json
import os
from pathlib import Path

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule

# Nikto uses OSVDB IDs and its own severity scale (not standardized).
# We map based on the item type and description.
TUNING_SEVERITY = {
    "1": Severity.INFO,       # Interesting file / seen in logs
    "2": Severity.MEDIUM,     # Misconfiguration / default file
    "3": Severity.HIGH,       # Information disclosure
    "4": Severity.HIGH,       # Injection (XSS/Script/HTML)
    "5": Severity.MEDIUM,     # Remote file retrieval (inside web root)
    "6": Severity.HIGH,       # Denial of service
    "7": Severity.HIGH,       # Remote file retrieval (server wide)
    "8": Severity.HIGH,       # Command execution / remote shell
    "9": Severity.CRITICAL,   # SQL injection
    "0": Severity.LOW,        # File upload
    "a": Severity.MEDIUM,     # Authentication bypass
    "b": Severity.LOW,        # Software identification
    "c": Severity.MEDIUM,     # Remote source inclusion
    "d": Severity.INFO,       # WebService
    "e": Severity.LOW,        # Administrative console
}


class NiktoModule(BaseModule):
    name = "nikto"
    tool_binary = "nikto.pl"
    description = "Web server misconfiguration scanner"

    def _perl_env(self) -> dict:
        """Return env vars needed for Perl modules (if installed locally)."""
        local_lib = Path.home() / "perl5" / "lib" / "perl5"
        if local_lib.is_dir():
            existing = os.environ.get("PERL5LIB", "")
            return {"PERL5LIB": f"{local_lib}:{existing}" if existing else str(local_lib)}
        return {}

    def get_version(self) -> str:
        try:
            result = self.run_command([self.tool_binary, "-Version"], env=self._perl_env())
            output = self.strip_ansi(result.stdout + result.stderr)
            for line in output.splitlines():
                if "nikto" in line.lower() and ("." in line or "v" in line.lower()):
                    return line.strip()
            return "unknown"
        except Exception:
            return "unknown"

    def execute(self, target: str) -> list[Finding]:
        mod_config = self.config.get("modules", {}).get("nikto", {})
        timeout = mod_config.get("timeout", 600)

        tmp_path = self._raw_file_path("nikto-raw.json")

        cmd = [
            self.tool_binary,
            "-h", target,
            "-Format", "json",
            "-output", tmp_path,
            "-nointeractive",
        ]

        tuning = mod_config.get("tuning", "")
        if tuning:
            cmd.extend(["-Tuning", tuning])

        self.run_command(cmd, timeout=timeout, env=self._perl_env())

        try:
            with open(tmp_path, "r") as f:
                raw = f.read()
        except FileNotFoundError:
            raw = "{}"

        return self.parse_output(raw)

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        # Nikto JSON structure varies; handle both flat and nested
        hosts = data if isinstance(data, list) else [data]

        for host_data in hosts:
            vulnerabilities = host_data.get("vulnerabilities", [])
            host_ip = host_data.get("ip", "")
            host_port = host_data.get("port", "")

            for vuln in vulnerabilities:
                osvdb_id = str(vuln.get("OSVDB", vuln.get("id", "")))
                method = vuln.get("method", "GET")
                url = vuln.get("url", "")
                msg = vuln.get("msg", "")

                # Determine severity from tuning category if available
                tuning_id = str(vuln.get("tuning", "b"))
                severity = TUNING_SEVERITY.get(tuning_id, Severity.MEDIUM)

                location = url
                if host_ip and not url.startswith("http"):
                    location = f"{host_ip}:{host_port}{url}"

                findings.append(Finding(
                    title=f"[nikto] {msg[:100]}",
                    severity=severity,
                    category=Category.MISCONFIGURATION,
                    source=self.name,
                    description=msg,
                    location=location,
                    evidence=f"{method} {url}",
                    reference=f"OSVDB-{osvdb_id}" if osvdb_id and osvdb_id != "0" else "",
                    metadata={
                        "osvdb": osvdb_id,
                        "method": method,
                        "tuning": tuning_id,
                    },
                ))

        return findings
