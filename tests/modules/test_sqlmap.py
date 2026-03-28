"""Tests for the SQLMap module output parsing."""

from webscan.models import Category, Severity
from webscan.modules.sqlmap import SqlmapModule


def _make_module():
    return SqlmapModule({"target": "https://example.com"})


SAMPLE_OUTPUT = """[INFO] testing connection to the target URL
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] Parameter: id (GET)
    Type: boolean-based blind
[INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
[INFO] sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
---
[INFO] the back-end DBMS is MySQL
[INFO] back-end DBMS: MySQL >= 5.0
"""

CLEAN_OUTPUT = """[INFO] testing connection to the target URL
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] Parameter: id (GET)
[INFO] GET parameter 'id' does not appear to be injectable
[INFO] no parameter(s) found for testing
"""

WAF_OUTPUT = """[WARNING] WAF/IPS/IDS detected on target
[INFO] checking if the target is protected by some kind of WAF/IPS
"""


class TestSqlmapParseOutput:
    def test_detects_injection(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        injections = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(injections) >= 1
        assert any("SQL injection" in f.title for f in injections)

    def test_detects_dbms(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        dbms = [f for f in findings if "DBMS" in f.title]
        assert len(dbms) >= 1
        assert "MySQL" in dbms[0].description

    def test_injection_metadata(self):
        module = _make_module()
        findings = module.parse_output(SAMPLE_OUTPUT)
        injection = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert injection.category == Category.INJECTION
        assert "CWE-89" in injection.reference

    def test_clean_output_no_findings(self):
        module = _make_module()
        findings = module.parse_output(CLEAN_OUTPUT)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_waf_detection(self):
        module = _make_module()
        findings = module.parse_output(WAF_OUTPUT)
        waf = [f for f in findings if "WAF" in f.title]
        assert len(waf) == 1

    def test_empty_input(self):
        module = _make_module()
        assert module.parse_output("") == []
