"""Trivy wrapper module."""

import json

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

CLASS_TO_CATEGORY = {
    "os-pkgs": Category.DEPENDENCY,
    "lang-pkgs": Category.DEPENDENCY,
    "config": Category.MISCONFIGURATION,
    "secret": Category.SECRET,
    "license": Category.CODE,
}


class TrivyModule(BaseModule):
    name = "trivy"
    tool_binary = "trivy"
    description = "Dependency and container vulnerability scanner"
    target_type = "source"

    def get_version(self) -> str:
        try:
            result = self.run_command([self.tool_binary, "version", "--format", "json"])
            data = json.loads(result.stdout)
            return data.get("Version", "unknown")
        except Exception:
            try:
                result = self.run_command([self.tool_binary, "version"])
                return self.strip_ansi(result.stdout.strip().splitlines()[0])
            except Exception:
                return "unknown"

    def execute(self, target: str) -> list[Finding]:
        mod_config = self.config.get("modules", {}).get("trivy", {})
        timeout = mod_config.get("timeout", 600)
        scan_type = mod_config.get("scan_type", "fs")
        image_name = mod_config.get("image_name", "")

        if scan_type == "image" and image_name:
            cmd = [self.tool_binary, "image", "--format", "json", image_name]
        else:
            cmd = [self.tool_binary, "fs", "--format", "json", target]

        result = self.run_command(cmd, timeout=timeout)
        return self.parse_output(result.stdout)

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        # Trivy JSON has a "Results" array
        results = data.get("Results", [])
        for result_block in results:
            target_name = result_block.get("Target", "")
            result_class = result_block.get("Class", "")
            category = CLASS_TO_CATEGORY.get(result_class, Category.DEPENDENCY)

            # Vulnerabilities
            for vuln in result_block.get("Vulnerabilities", []):
                vuln_id = vuln.get("VulnerabilityID", "")
                pkg_name = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                sev_str = vuln.get("Severity", "UNKNOWN").upper()
                severity = SEVERITY_MAP.get(sev_str, Severity.INFO)
                title = vuln.get("Title", f"{vuln_id} in {pkg_name}")
                description = vuln.get("Description", "")

                remediation = ""
                if fixed:
                    remediation = f"Upgrade {pkg_name} from {installed} to {fixed}"

                findings.append(Finding(
                    title=f"[trivy] {title}",
                    severity=severity,
                    category=category,
                    source=self.name,
                    description=description[:500],
                    location=f"{target_name} ({pkg_name}@{installed})",
                    evidence=f"Installed: {installed}, Fixed: {fixed}" if fixed else f"Installed: {installed}",
                    remediation=remediation,
                    reference=vuln_id,
                    metadata={
                        "vuln_id": vuln_id,
                        "pkg_name": pkg_name,
                        "installed_version": installed,
                        "fixed_version": fixed,
                        "data_source": vuln.get("DataSource", {}),
                    },
                ))

            # Misconfigurations
            for misconfig in result_block.get("Misconfigurations", []):
                mc_id = misconfig.get("ID", "")
                mc_title = misconfig.get("Title", mc_id)
                sev_str = misconfig.get("Severity", "MEDIUM").upper()
                severity = SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

                findings.append(Finding(
                    title=f"[trivy] {mc_title}",
                    severity=severity,
                    category=Category.MISCONFIGURATION,
                    source=self.name,
                    description=misconfig.get("Description", ""),
                    location=target_name,
                    evidence=misconfig.get("Message", ""),
                    remediation=misconfig.get("Resolution", ""),
                    reference=mc_id,
                    metadata={
                        "id": mc_id,
                        "type": misconfig.get("Type", ""),
                    },
                ))

            # Secrets
            for secret in result_block.get("Secrets", []):
                findings.append(Finding(
                    title=f"[trivy] Secret: {secret.get('Title', 'Unknown')}",
                    severity=Severity.HIGH,
                    category=Category.SECRET,
                    source=self.name,
                    description=secret.get("Match", ""),
                    location=f"{target_name}:{secret.get('StartLine', '')}",
                    remediation="Remove or rotate the exposed secret",
                    reference=secret.get("RuleID", ""),
                ))

        return findings
