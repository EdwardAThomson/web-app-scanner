"""Tests for the Trivy module output parsing."""

import json

from webscan.models import Category, Severity
from webscan.modules.trivy import TrivyModule


def _make_module():
    return TrivyModule({"target": "/path/to/project"})


SAMPLE_OUTPUT = json.dumps({
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                    "Title": "Prototype Pollution in lodash",
                    "Description": "lodash before 4.17.21 is vulnerable to prototype pollution.",
                },
                {
                    "VulnerabilityID": "CVE-2023-5678",
                    "PkgName": "express",
                    "InstalledVersion": "4.17.1",
                    "FixedVersion": "",
                    "Severity": "LOW",
                    "Title": "Minor info leak in express",
                    "Description": "Express leaks version info.",
                },
            ],
            "Misconfigurations": [],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Vulnerabilities": [],
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be root",
                    "Severity": "HIGH",
                    "Description": "Running as root is a security risk.",
                    "Message": "Last USER command is root",
                    "Resolution": "Add a USER directive to switch to non-root",
                    "Type": "dockerfile",
                },
            ],
        },
    ],
})


class TestTrivyParseOutput:
    def test_parses_vulnerabilities(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        vuln_findings = [f for f in findings if f.category == Category.DEPENDENCY]
        assert len(vuln_findings) == 2

    def test_parses_misconfigurations(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        misconfig_findings = [f for f in findings if f.category == Category.MISCONFIGURATION]
        assert len(misconfig_findings) == 1

    def test_severity_mapping(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        lodash = [f for f in findings if "lodash" in f.title][0]
        assert lodash.severity == Severity.HIGH
        express = [f for f in findings if "express" in f.title.lower()][0]
        assert express.severity == Severity.LOW

    def test_remediation_with_fix(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        lodash = [f for f in findings if "lodash" in f.title][0]
        assert "4.17.21" in lodash.remediation
        # Express has no fix version
        express = [f for f in findings if "express" in f.title.lower()][0]
        assert express.remediation == ""

    def test_reference(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert findings[0].reference == "CVE-2023-1234"

    def test_empty_input(self):
        module = _make_module()
        assert module.parse_output("") == []

    def test_no_results(self):
        module = _make_module()
        assert module.parse_output(json.dumps({"Results": []})) == []
