"""Tests for the Nikto module output parsing."""

import json

from webscan.models import Category, Severity
from webscan.modules.nikto import NiktoModule


def _make_module():
    return NiktoModule({"target": "https://example.com"})


SAMPLE_OUTPUT = json.dumps({
    "ip": "93.184.216.34",
    "port": "443",
    "vulnerabilities": [
        {
            "OSVDB": "3092",
            "method": "GET",
            "url": "/admin/",
            "msg": "This might be interesting: admin directory found.",
            "tuning": "2",
        },
        {
            "OSVDB": "0",
            "method": "GET",
            "url": "/",
            "msg": "Server leaks inodes via ETags",
            "tuning": "3",
        },
        {
            "OSVDB": "877",
            "method": "GET",
            "url": "/cgi-bin/test.cgi",
            "msg": "CGI script found that may allow command injection.",
            "tuning": "8",
        },
    ],
})


class TestNiktoParseOutput:
    def test_parses_findings(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert len(findings) == 3

    def test_severity_from_tuning(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        # tuning 2 = MEDIUM, 3 = HIGH, 8 = HIGH
        assert findings[0].severity == Severity.MEDIUM
        assert findings[1].severity == Severity.HIGH
        assert findings[2].severity == Severity.HIGH

    def test_category_is_misconfiguration(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        for f in findings:
            assert f.category == Category.MISCONFIGURATION

    def test_osvdb_reference(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert findings[0].reference == "OSVDB-3092"
        assert findings[1].reference == ""  # OSVDB 0 means no reference

    def test_empty_input(self):
        module = _make_module()
        assert module.parse_output("{}") == []

    def test_invalid_json(self):
        module = _make_module()
        assert module.parse_output("not json") == []

    def test_list_format(self):
        """Nikto sometimes outputs a list of host objects."""
        data = json.dumps([{
            "ip": "1.2.3.4",
            "port": "80",
            "vulnerabilities": [
                {"OSVDB": "1", "method": "GET", "url": "/test", "msg": "test", "tuning": "b"},
            ],
        }])
        module = _make_module()
        findings = module.parse_output(data)
        assert len(findings) == 1
