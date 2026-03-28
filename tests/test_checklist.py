"""Tests for the checklist data model."""

from webscan.checklist import (
    CHECKLIST,
    Coverage,
    ItemStatus,
    get_active_items,
    get_checklist,
    get_coverage_summary,
)


class TestChecklistData:
    def test_checklist_not_empty(self):
        assert len(CHECKLIST) > 50

    def test_all_items_have_ids(self):
        for item in CHECKLIST:
            assert item.id, f"Item missing ID: {item.title}"

    def test_unique_ids(self):
        ids = [item.id for item in CHECKLIST]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found"

    def test_all_items_have_category(self):
        for item in CHECKLIST:
            assert item.category, f"Item {item.id} missing category"

    def test_severity_range(self):
        for item in CHECKLIST:
            assert 0 <= item.severity <= 4, f"Item {item.id} has invalid severity: {item.severity}"


class TestActiveItems:
    def test_deprecated_excluded(self):
        active = get_active_items()
        for item in active:
            assert item.status != ItemStatus.DEPRECATED

    def test_fewer_than_total(self):
        assert len(get_active_items()) < len(CHECKLIST)


class TestCoverageSummary:
    def test_all_modules_run(self):
        modules = [
            "testssl", "headers", "nuclei", "nikto", "semgrep",
            "trivy", "gitleaks", "ffuf", "sqlmap", "api_routes",
            "disclosure", "session", "forms",
        ]
        summary = get_coverage_summary(modules)
        assert summary["total_items"] > 0
        assert summary["coverage_percent"] > 0
        assert summary["automated"] > 0

    def test_no_modules_run(self):
        summary = get_coverage_summary([])
        assert summary["automated"] == 0
        assert summary["partial"] == 0
        # Manual items should still be counted
        assert summary["manual"] > 0

    def test_single_module(self):
        summary = get_coverage_summary(["headers"])
        assert summary["automated"] > 0
        # Should have many not_covered since only one module ran
        assert summary["not_covered"] > summary["automated"]

    def test_percentages_valid(self):
        summary = get_coverage_summary(["testssl", "headers"])
        assert 0 <= summary["coverage_percent"] <= 100
