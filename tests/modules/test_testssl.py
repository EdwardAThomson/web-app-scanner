"""Tests for the testssl.sh module output parsing."""

import json

from webscan.models import Category, Severity
from webscan.modules.testssl import TestSSLModule


def _make_module():
    return TestSSLModule({"target": "https://example.com"})


SAMPLE_OUTPUT = json.dumps([
    {
        "id": "BEAST",
        "severity": "HIGH",
        "finding": "BEAST (CVE-2011-3389) -- TLS1: ECDHE-RSA-AES128-SHA",
        "ip": "93.184.216.34",
        "port": "443",
        "cve": "CVE-2011-3389",
        "cwe": "CWE-327",
    },
    {
        "id": "POODLE_SSL",
        "severity": "CRITICAL",
        "finding": "POODLE (CVE-2014-3566) -- SSLv3 is offered",
        "ip": "93.184.216.34",
        "port": "443",
        "cve": "CVE-2014-3566",
        "cwe": "",
    },
    {
        "id": "cert_chain",
        "severity": "OK",
        "finding": "Certificate chain is complete",
        "ip": "93.184.216.34",
        "port": "443",
    },
    {
        "id": "HSTS",
        "severity": "WARN",
        "finding": "No HSTS header",
        "ip": "93.184.216.34",
        "port": "443",
    },
])


class TestTestSSLParseOutput:
    def test_parses_findings(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        # OK entry should be skipped
        assert len(findings) == 3

    def test_skips_ok_entries(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        titles = [f.title for f in findings]
        assert not any("cert_chain" in t for t in titles)

    def test_severity_mapping(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        severities = {f.title.split(":")[0]: f.severity for f in findings}
        # BEAST is HIGH
        beast = [f for f in findings if "BEAST" in f.title][0]
        assert beast.severity == Severity.HIGH
        # POODLE is CRITICAL
        poodle = [f for f in findings if "POODLE" in f.title][0]
        assert poodle.severity == Severity.CRITICAL
        # WARN maps to MEDIUM
        hsts = [f for f in findings if "HSTS" in f.title][0]
        assert hsts.severity == Severity.MEDIUM

    def test_category_is_tls(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        for f in findings:
            assert f.category == Category.TLS

    def test_cve_in_reference(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        beast = [f for f in findings if "BEAST" in f.title][0]
        assert "CVE-2011-3389" in beast.reference

    def test_empty_input(self):
        module = _make_module()
        assert module.parse_output("") == []

    def test_invalid_json(self):
        module = _make_module()
        assert module.parse_output("not json") == []

    def test_nested_scan_result_format(self):
        """testssl.sh sometimes wraps results in a scanResult array."""
        nested = json.dumps([{
            "protocols": [
                {"id": "SSLv3", "severity": "CRITICAL", "finding": "SSLv3 offered", "ip": "1.2.3.4", "port": "443"}
            ],
            "ciphers": [],
            "serverDefaults": [],
            "headerResponse": [],
            "vulnerabilities": [
                {"id": "BEAST", "severity": "HIGH", "finding": "BEAST vuln", "ip": "1.2.3.4", "port": "443", "cve": "CVE-2011-3389"}
            ],
            "fs": [],
        }])
        module = _make_module()
        findings = module.parse_output(nested)
        assert len(findings) == 2
