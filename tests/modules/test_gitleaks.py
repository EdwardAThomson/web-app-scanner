"""Tests for the Gitleaks module output parsing."""

import json

from webscan.models import Category, Severity
from webscan.modules.gitleaks import GitleaksModule


def _make_module():
    return GitleaksModule({"target": "/path/to/repo"})


SAMPLE_OUTPUT = json.dumps([
    {
        "RuleID": "aws-access-key",
        "Description": "AWS Access Key",
        "File": "config/settings.py",
        "StartLine": 42,
        "Commit": "abc123def456",
        "Match": "AKIAIOSFODNN7EXAMPLE",
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "Author": "dev",
        "Email": "dev@example.com",
        "Date": "2024-01-15",
        "Tags": ["aws", "key"],
        "Entropy": 3.5,
    },
    {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "src/api.js",
        "StartLine": 10,
        "Commit": "789abc",
        "Match": "api_key=sk_live_abc",
        "Secret": "sk_live_abc",
        "Author": "dev",
        "Email": "dev@example.com",
        "Date": "2024-02-01",
        "Tags": [],
        "Entropy": 4.2,
    },
])


class TestGitleaksParseOutput:
    def test_parses_findings(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert len(findings) == 2

    def test_finding_severity(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        for f in findings:
            assert f.severity == Severity.HIGH
            assert f.category == Category.SECRET

    def test_finding_location(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert findings[0].location == "config/settings.py:42"
        assert findings[1].location == "src/api.js:10"

    def test_secret_redaction(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        # Secret should be redacted — not contain the full value
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].evidence
        # But should contain partial hint
        assert "AKI" in findings[0].evidence
        assert "PLE" in findings[0].evidence

    def test_metadata(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert findings[0].metadata["rule_id"] == "aws-access-key"
        assert findings[0].metadata["commit"] == "abc123def456"
        assert findings[0].metadata["entropy"] == 3.5

    def test_empty_input(self):
        module = _make_module()
        assert module.parse_output("[]") == []

    def test_invalid_json(self):
        module = _make_module()
        assert module.parse_output("not json") == []

    def test_short_secret_fully_redacted(self):
        data = json.dumps([{
            "RuleID": "short-key",
            "Description": "Short Key",
            "File": "a.txt",
            "StartLine": 1,
            "Commit": "abc",
            "Match": "key=ab",
            "Secret": "ab",
        }])
        module = _make_module()
        findings = module.parse_output(data)
        assert "ab" not in findings[0].evidence or "***" in findings[0].evidence
