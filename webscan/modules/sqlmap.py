"""SQLMap wrapper module."""

import json
import os
import tempfile

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule


class SqlmapModule(BaseModule):
    name = "sqlmap"
    tool_binary = "sqlmap"
    description = "Automated SQL injection detection"

    def get_version(self) -> str:
        try:
            result = self.run_command([
                self._python(), self._sqlmap_path(), "--version"
            ])
            return self.strip_ansi(result.stdout.strip())
        except Exception:
            return "unknown"

    def _python(self) -> str:
        """Get the Python interpreter path."""
        import sys
        return sys.executable

    def _sqlmap_path(self) -> str:
        """Get the sqlmap.py script path."""
        import shutil
        # Check if sqlmap is a symlink to sqlmap.py
        path = shutil.which(self.tool_binary)
        if path:
            real = os.path.realpath(path)
            if real.endswith(".py"):
                return real
            return path
        return self.tool_binary

    def check_installed(self) -> tuple[bool, str]:
        path = self._sqlmap_path()
        if os.path.isfile(path):
            return True, path
        return False, f"{self.tool_binary} not found"

    def execute(self, target: str) -> list[Finding]:
        mod_config = self.config.get("modules", {}).get("sqlmap", {})
        timeout = mod_config.get("timeout", 600)

        output_dir = tempfile.mkdtemp(prefix="sqlmap-")

        cmd = [
            self._python(),
            self._sqlmap_path(),
            "-u", target,
            "--batch",            # Non-interactive
            "--output-dir", output_dir,
            "--level", str(mod_config.get("level", 1)),
            "--risk", str(mod_config.get("risk", 1)),
        ]

        if mod_config.get("forms", False):
            cmd.append("--forms")

        if mod_config.get("crawl", False):
            cmd.extend(["--crawl", str(mod_config.get("crawl_depth", 2))])

        result = self.run_command(cmd, timeout=timeout)

        # SQLMap writes to stdout — combine with stderr for full picture
        return self.parse_output(result.stdout + "\n" + result.stderr)

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        lines = raw_output.splitlines()

        current_param = ""
        current_type = ""

        for line in lines:
            stripped = line.strip()

            # Detect parameter being tested
            if "Parameter:" in stripped:
                current_param = stripped.split("Parameter:")[-1].strip()

            # Detect injection type
            if "Type:" in stripped and current_param:
                current_type = stripped.split("Type:")[-1].strip()

            # Detect confirmed injection (exclude "not injectable" / "does not appear")
            lower = stripped.lower()
            is_positive = (
                ("is vulnerable" in lower and "not vulnerable" not in lower)
                or ("injectable" in lower and "not" not in lower.split("injectable")[0][-20:])
            )
            if is_positive:
                findings.append(Finding(
                    title=f"[sqlmap] SQL injection: {current_param}",
                    severity=Severity.CRITICAL,
                    category=Category.INJECTION,
                    source=self.name,
                    description=f"SQL injection found in parameter '{current_param}' ({current_type})",
                    location=current_param,
                    evidence=stripped,
                    remediation="Use parameterized queries / prepared statements. Never interpolate user input into SQL.",
                    reference="CWE-89",
                    metadata={
                        "parameter": current_param,
                        "injection_type": current_type,
                    },
                ))

            # Detect DBMS identification
            if "back-end dbms" in stripped.lower() and ":" in stripped:
                dbms = stripped.split(":", 1)[-1].strip()
                findings.append(Finding(
                    title=f"[sqlmap] Backend DBMS identified: {dbms}",
                    severity=Severity.INFO,
                    category=Category.INJECTION,
                    source=self.name,
                    description=f"Database management system identified: {dbms}",
                    location=current_param,
                    evidence=stripped,
                    metadata={"dbms": dbms},
                ))

            # Detect WAF/IPS (only match the detection line, not follow-up checks)
            if "WAF/IPS" in stripped and "detected" in stripped.lower():
                findings.append(Finding(
                    title="[sqlmap] WAF/IPS detected",
                    severity=Severity.INFO,
                    category=Category.MISCONFIGURATION,
                    source=self.name,
                    description=stripped,
                    location="",
                    evidence=stripped,
                ))

        return findings
