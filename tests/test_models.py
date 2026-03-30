"""Tests for webscan data models."""

from datetime import datetime

from webscan.models import (
    Category,
    Finding,
    ModuleResult,
    ScanResult,
    Severity,
)


def _make_finding(**overrides) -> Finding:
    defaults = {
        "title": "Test finding",
        "severity": Severity.MEDIUM,
        "category": Category.HEADER,
        "source": "test",
        "description": "A test finding",
        "location": "https://example.com",
    }
    defaults.update(overrides)
    return Finding(**defaults)


class TestFinding:
    def test_to_dict_serializes_enums(self):
        f = _make_finding()
        d = f.to_dict()
        assert d["severity"] == "medium"
        assert d["category"] == "header"

    def test_to_dict_includes_all_fields(self):
        f = _make_finding(evidence="some evidence", reference="CVE-2024-1234")
        d = f.to_dict()
        assert d["title"] == "Test finding"
        assert d["evidence"] == "some evidence"
        assert d["reference"] == "CVE-2024-1234"
        assert d["metadata"] == {}

    def test_metadata_preserved(self):
        f = _make_finding(metadata={"template_id": "cve-2024-1234"})
        d = f.to_dict()
        assert d["metadata"]["template_id"] == "cve-2024-1234"


class TestModuleResult:
    def test_to_dict_with_findings(self):
        mr = ModuleResult(
            module_name="headers",
            success=True,
            findings=[_make_finding(), _make_finding(severity=Severity.HIGH)],
            duration_seconds=1.5,
        )
        d = mr.to_dict()
        assert d["module_name"] == "headers"
        assert d["success"] is True
        assert len(d["findings"]) == 2
        assert d["findings"][0]["severity"] == "medium"
        assert d["findings"][1]["severity"] == "high"

    def test_to_dict_failed_module(self):
        mr = ModuleResult(
            module_name="testssl",
            success=False,
            error="testssl.sh not found in PATH",
        )
        d = mr.to_dict()
        assert d["success"] is False
        assert "not found" in d["error"]
        assert d["findings"] == []


class TestScanResult:
    def test_all_findings_aggregates(self):
        sr = ScanResult(
            target="https://example.com",
            module_results=[
                ModuleResult(module_name="a", success=True, findings=[_make_finding()]),
                ModuleResult(module_name="b", success=True, findings=[_make_finding(), _make_finding()]),
            ],
        )
        assert len(sr.all_findings) == 3

    def test_summary(self):
        sr = ScanResult(
            target="https://example.com",
            module_results=[
                ModuleResult(
                    module_name="headers",
                    success=True,
                    findings=[
                        _make_finding(severity=Severity.HIGH),
                        _make_finding(severity=Severity.HIGH),
                        _make_finding(severity=Severity.LOW),
                    ],
                ),
                ModuleResult(module_name="testssl", success=False, error="missing"),
            ],
        )
        s = sr.summary()
        assert s["target"] == "https://example.com"
        assert s["total_findings"] == 3
        assert s["by_severity"] == {"high": 2, "low": 1}
        assert s["modules_run"] == 2
        assert s["modules_failed"] == 1

    def test_to_dict(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        sr = ScanResult(target="https://example.com", started_at=now)
        d = sr.to_dict()
        assert d["target"] == "https://example.com"
        assert d["started_at"] == "2026-01-01T12:00:00"
        assert d["finished_at"] is None
        assert "summary" in d
        assert "module_results" in d

    def test_empty_scan(self):
        sr = ScanResult(target="https://example.com")
        assert sr.all_findings == []
        s = sr.summary()
        assert s["total_findings"] == 0
        assert s["modules_run"] == 0


class TestSeverityRank:
    def test_ordering(self):
        assert Severity.rank(Severity.CRITICAL) > Severity.rank(Severity.HIGH)
        assert Severity.rank(Severity.HIGH) > Severity.rank(Severity.MEDIUM)
        assert Severity.rank(Severity.MEDIUM) > Severity.rank(Severity.LOW)
        assert Severity.rank(Severity.LOW) > Severity.rank(Severity.INFO)

    def test_all_values_mapped(self):
        for sev in Severity:
            assert isinstance(Severity.rank(sev), int)
