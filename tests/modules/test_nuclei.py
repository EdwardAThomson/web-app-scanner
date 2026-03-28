"""Tests for the Nuclei module output parsing."""

import json

from webscan.models import Severity
from webscan.modules.nuclei import NucleiModule


def _make_module():
    return NucleiModule({"target": "https://example.com"})


SAMPLE_JSONL = """{"template-id":"cve-2021-44228","info":{"name":"Log4j RCE","severity":"critical","description":"Apache Log4j2 Remote Code Execution","tags":["cve","rce"],"classification":{"cve-id":"CVE-2021-44228"},"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],"remediation":"Upgrade Log4j to 2.17.0+"},"type":"http","matched-at":"https://example.com/api","matcher-name":"log4j"}
{"template-id":"tech-detect","info":{"name":"Nginx Detected","severity":"info","description":"Nginx web server detected","tags":["tech"]},"type":"http","matched-at":"https://example.com","matcher-name":"nginx"}
{"template-id":"missing-hsts","info":{"name":"Missing HSTS","severity":"medium","description":"HSTS header not found","tags":["misconfiguration"],"remediation":"Add HSTS header"},"type":"http","matched-at":"https://example.com"}"""


class TestNucleiParseOutput:
    def test_parses_jsonl(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_JSONL)
        assert len(findings) == 3

    def test_severity_mapping(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_JSONL)
        assert findings[0].severity == Severity.CRITICAL
        assert findings[1].severity == Severity.INFO
        assert findings[2].severity == Severity.MEDIUM

    def test_finding_fields(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_JSONL)
        f = findings[0]
        assert "Log4j RCE" in f.title
        assert f.location == "https://example.com/api"
        assert "CVE-2021-44228" in f.reference
        assert "Upgrade" in f.remediation
        assert f.metadata["template_id"] == "cve-2021-44228"

    def test_empty_input(self):
        module = _make_module()
        assert module.parse_output("") == []

    def test_invalid_json_lines_skipped(self):
        module = _make_module()
        raw = "not json\n" + SAMPLE_JSONL.splitlines()[0]
        findings = module.parse_output(raw)
        assert len(findings) == 1

    def test_references_list(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_JSONL)
        # First finding has CVE in classification, so reference should be the CVE
        assert "CVE-2021-44228" in findings[0].reference
