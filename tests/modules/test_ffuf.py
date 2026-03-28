"""Tests for the ffuf module output parsing."""

import json

from webscan.models import Category, Severity
from webscan.modules.ffuf import FfufModule


def _make_module():
    return FfufModule({"target": "https://example.com"})


SAMPLE_OUTPUT = json.dumps({
    "results": [
        {
            "input": {"FUZZ": "admin"},
            "url": "https://example.com/admin",
            "status": 200,
            "length": 1234,
            "words": 56,
            "redirectlocation": "",
        },
        {
            "input": {"FUZZ": "api"},
            "url": "https://example.com/api",
            "status": 301,
            "length": 0,
            "words": 0,
            "redirectlocation": "https://example.com/api/",
        },
        {
            "input": {"FUZZ": "secret"},
            "url": "https://example.com/secret",
            "status": 403,
            "length": 199,
            "words": 10,
            "redirectlocation": "",
        },
        {
            "input": {"FUZZ": "login"},
            "url": "https://example.com/login",
            "status": 401,
            "length": 50,
            "words": 5,
            "redirectlocation": "",
        },
    ],
})


class TestFfufParseOutput:
    def test_parses_findings(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        assert len(findings) == 4

    def test_severity_by_status(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        by_input = {f.metadata["input"]: f for f in findings}
        assert by_input["admin"].severity == Severity.INFO    # 200
        assert by_input["api"].severity == Severity.INFO       # 301
        assert by_input["secret"].severity == Severity.LOW     # 403
        assert by_input["login"].severity == Severity.LOW      # 401

    def test_category_is_fuzzing(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        for f in findings:
            assert f.category == Category.FUZZING

    def test_metadata(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        admin = [f for f in findings if f.metadata["input"] == "admin"][0]
        assert admin.metadata["status_code"] == 200
        assert admin.metadata["content_length"] == 1234

    def test_redirect_info(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        api = [f for f in findings if f.metadata["input"] == "api"][0]
        assert "redirect" in api.description.lower() or api.metadata["redirect"]

    def test_empty_input(self):
        module = _make_module()
        assert module.parse_output("") == []

    def test_no_results(self):
        module = _make_module()
        assert module.parse_output(json.dumps({"results": []})) == []
