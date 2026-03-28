"""Tests for the Semgrep module output parsing."""

import json

from webscan.models import Category, Severity
from webscan.modules.semgrep import SemgrepModule


def _make_module():
    return SemgrepModule({"target": "/path/to/project"})


SAMPLE_OUTPUT = json.dumps({
    "results": [
        {
            "check_id": "javascript.express.security.injection.sql-injection",
            "path": "src/db.js",
            "start": {"line": 42, "col": 5},
            "extra": {
                "message": "Detected SQL injection via string concatenation",
                "severity": "ERROR",
                "lines": "const query = `SELECT * FROM users WHERE id = ${req.params.id}`",
                "metadata": {
                    "category": "security",
                    "cwe": ["CWE-89"],
                    "owasp": ["A03:2021"],
                    "confidence": "HIGH",
                    "technology": ["express"],
                },
            },
        },
        {
            "check_id": "javascript.lang.best-practice.no-console-log",
            "path": "src/app.js",
            "start": {"line": 10, "col": 1},
            "extra": {
                "message": "Avoid console.log in production code",
                "severity": "INFO",
                "lines": "console.log('server started')",
                "metadata": {
                    "category": "best-practice",
                },
            },
        },
    ],
})


class TestSemgrepParseOutput:
    def test_parses_findings(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert len(findings) == 2

    def test_severity_mapping(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert findings[0].severity == Severity.HIGH    # ERROR -> HIGH
        assert findings[1].severity == Severity.LOW      # INFO -> LOW

    def test_security_category(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert findings[0].category == Category.VULNERABILITY
        assert findings[1].category == Category.CODE

    def test_location(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert findings[0].location == "src/db.js:42"

    def test_cwe_reference(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert "CWE-89" in findings[0].reference

    def test_evidence(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert "SELECT" in findings[0].evidence

    def test_empty_input(self):
        module = _make_module()
        assert module.parse_output("") == []

    def test_no_results(self):
        module = _make_module()
        assert module.parse_output(json.dumps({"results": []})) == []
