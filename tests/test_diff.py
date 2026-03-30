"""Tests for baseline diff logic."""

import json
import os
import tempfile

from webscan.diff import DiffResult, compute_diff, load_baseline
from webscan.models import Category, Finding, Severity


def _f(title="Finding", severity=Severity.HIGH, location="https://example.com",
       source="headers", **kw) -> Finding:
    return Finding(
        title=title, severity=severity, category=Category.HEADER,
        source=source, description="desc", location=location, **kw,
    )


# ---------------------------------------------------------------------------
# compute_diff
# ---------------------------------------------------------------------------

class TestComputeDiff:
    def test_all_new(self):
        result = compute_diff(baseline=[], current=[_f("A"), _f("B")])
        assert result.summary() == {"new": 2, "fixed": 0, "persistent": 0}

    def test_all_fixed(self):
        result = compute_diff(baseline=[_f("A"), _f("B")], current=[])
        assert result.summary() == {"new": 0, "fixed": 2, "persistent": 0}

    def test_all_persistent(self):
        baseline = [_f("A"), _f("B")]
        current = [_f("A"), _f("B")]
        result = compute_diff(baseline, current)
        assert result.summary() == {"new": 0, "fixed": 0, "persistent": 2}

    def test_mixed(self):
        baseline = [_f("A"), _f("B"), _f("C")]
        current = [_f("B"), _f("C"), _f("D")]
        result = compute_diff(baseline, current)
        assert result.summary() == {"new": 1, "fixed": 1, "persistent": 2}
        assert result.new[0].title == "D"
        assert result.fixed[0].title == "A"

    def test_case_insensitive_matching(self):
        baseline = [_f("Missing HSTS")]
        current = [_f("missing hsts")]
        result = compute_diff(baseline, current)
        assert result.summary()["persistent"] == 1
        assert result.summary()["new"] == 0

    def test_different_severity_is_not_same(self):
        baseline = [_f("Issue", severity=Severity.MEDIUM)]
        current = [_f("Issue", severity=Severity.HIGH)]
        result = compute_diff(baseline, current)
        # Reclassified severity = new finding + old one fixed
        assert result.summary() == {"new": 1, "fixed": 1, "persistent": 0}

    def test_different_location_is_not_same(self):
        baseline = [_f("Issue", location="https://example.com/a")]
        current = [_f("Issue", location="https://example.com/b")]
        result = compute_diff(baseline, current)
        assert result.summary() == {"new": 1, "fixed": 1, "persistent": 0}

    def test_sorted_by_severity(self):
        current = [
            _f("Low", severity=Severity.LOW),
            _f("Crit", severity=Severity.CRITICAL),
            _f("Med", severity=Severity.MEDIUM),
        ]
        result = compute_diff(baseline=[], current=current)
        assert [f.title for f in result.new] == ["Crit", "Med", "Low"]

    def test_persistent_uses_current_finding(self):
        baseline = [_f("A", source="old-module", evidence="old")]
        current = [_f("A", source="new-module", evidence="updated")]
        result = compute_diff(baseline, current)
        assert result.persistent[0].source == "new-module"
        assert result.persistent[0].evidence == "updated"

    def test_fixed_uses_baseline_finding(self):
        baseline = [_f("Gone", source="old-module", evidence="old-evidence")]
        result = compute_diff(baseline, current=[])
        assert result.fixed[0].source == "old-module"
        assert result.fixed[0].evidence == "old-evidence"

    def test_empty_both(self):
        result = compute_diff([], [])
        assert result.summary() == {"new": 0, "fixed": 0, "persistent": 0}


# ---------------------------------------------------------------------------
# DiffResult
# ---------------------------------------------------------------------------

class TestDiffResult:
    def test_to_dict(self):
        dr = DiffResult(
            new=[_f("New")],
            fixed=[_f("Fixed")],
            persistent=[_f("Same")],
        )
        d = dr.to_dict()
        assert len(d["new"]) == 1
        assert len(d["fixed"]) == 1
        assert len(d["persistent"]) == 1
        assert d["new"][0]["title"] == "New"

    def test_summary(self):
        dr = DiffResult(new=[_f("A")], fixed=[], persistent=[_f("B"), _f("C")])
        assert dr.summary() == {"new": 1, "fixed": 0, "persistent": 2}


# ---------------------------------------------------------------------------
# load_baseline
# ---------------------------------------------------------------------------

class TestLoadBaseline:
    def _write_json(self, data: dict) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        return path

    def test_loads_deduped_findings(self):
        data = {
            "deduped_findings": [
                {"title": "A", "severity": "high", "category": "header",
                 "source": "headers", "description": "d", "location": "/"},
                {"title": "B", "severity": "low", "category": "tls",
                 "source": "testssl", "description": "d", "location": "/"},
            ],
            "module_results": [],
        }
        path = self._write_json(data)
        try:
            findings = load_baseline(path)
            assert len(findings) == 2
            titles = {f.title for f in findings}
            assert titles == {"A", "B"}
        finally:
            os.unlink(path)

    def test_falls_back_to_module_results(self):
        data = {
            "module_results": [
                {
                    "module_name": "headers",
                    "success": True,
                    "findings": [
                        {"title": "X", "severity": "medium", "category": "header",
                         "source": "headers", "description": "d", "location": "/"},
                    ],
                },
                {
                    "module_name": "nuclei",
                    "success": True,
                    "findings": [
                        {"title": "Y", "severity": "high", "category": "vulnerability",
                         "source": "nuclei", "description": "d", "location": "/"},
                    ],
                },
            ],
        }
        path = self._write_json(data)
        try:
            findings = load_baseline(path)
            assert len(findings) == 2
        finally:
            os.unlink(path)

    def test_deduplicates_fallback(self):
        """When falling back to module_results, duplicates are merged."""
        finding_dict = {"title": "Same", "severity": "high", "category": "header",
                        "source": "headers", "description": "d", "location": "/"}
        data = {
            "module_results": [
                {"module_name": "a", "success": True, "findings": [finding_dict]},
                {"module_name": "b", "success": True, "findings": [finding_dict]},
            ],
        }
        path = self._write_json(data)
        try:
            findings = load_baseline(path)
            assert len(findings) == 1
        finally:
            os.unlink(path)

    def test_empty_report(self):
        data = {"module_results": [], "deduped_findings": []}
        path = self._write_json(data)
        try:
            findings = load_baseline(path)
            assert findings == []
        finally:
            os.unlink(path)
