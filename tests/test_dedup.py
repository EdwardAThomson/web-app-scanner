"""Tests for cross-module finding deduplication."""

from webscan.dedup import deduplicate, _dedup_key
from webscan.models import Category, Finding, Severity


def _make_finding(**overrides) -> Finding:
    defaults = {
        "title": "Missing X-Frame-Options header",
        "severity": Severity.HIGH,
        "category": Category.HEADER,
        "source": "headers",
        "description": "X-Frame-Options is not set.",
        "location": "https://example.com",
    }
    defaults.update(overrides)
    return Finding(**defaults)


class TestDedupKey:
    def test_same_title_case_insensitive(self):
        a = _make_finding(title="Missing HSTS")
        b = _make_finding(title="missing hsts")
        assert _dedup_key(a) == _dedup_key(b)

    def test_different_severity_different_key(self):
        a = _make_finding(severity=Severity.HIGH)
        b = _make_finding(severity=Severity.MEDIUM)
        assert _dedup_key(a) != _dedup_key(b)

    def test_different_location_different_key(self):
        a = _make_finding(location="https://example.com")
        b = _make_finding(location="https://example.com/admin")
        assert _dedup_key(a) != _dedup_key(b)

    def test_whitespace_stripped(self):
        a = _make_finding(title="  Missing HSTS  ", location="  https://example.com  ")
        b = _make_finding(title="Missing HSTS", location="https://example.com")
        assert _dedup_key(a) == _dedup_key(b)


class TestDeduplicate:
    def test_no_duplicates_unchanged(self):
        findings = [
            _make_finding(title="Finding A"),
            _make_finding(title="Finding B"),
        ]
        result = deduplicate(findings)
        assert len(result) == 2

    def test_exact_duplicates_merged(self):
        findings = [
            _make_finding(source="headers"),
            _make_finding(source="nuclei"),
            _make_finding(source="nikto"),
        ]
        result = deduplicate(findings)
        assert len(result) == 1
        assert result[0].metadata["sources"] == ["headers", "nikto", "nuclei"]
        assert result[0].metadata["duplicate_count"] == 3
        assert "headers" in result[0].source
        assert "nuclei" in result[0].source

    def test_best_description_kept(self):
        findings = [
            _make_finding(source="headers", description="Short."),
            _make_finding(source="nuclei", description="A much longer and more detailed description of the issue."),
        ]
        result = deduplicate(findings)
        assert "much longer" in result[0].description

    def test_best_evidence_kept(self):
        findings = [
            _make_finding(source="headers", evidence=""),
            _make_finding(source="nuclei", evidence="HTTP/1.1 200 OK\nX-Frame-Options: missing"),
        ]
        result = deduplicate(findings)
        assert "missing" in result[0].evidence

    def test_best_remediation_kept(self):
        findings = [
            _make_finding(source="headers", remediation="Add the header."),
            _make_finding(source="nuclei", remediation="Add X-Frame-Options: DENY or SAMEORIGIN to all responses."),
        ]
        result = deduplicate(findings)
        assert "DENY" in result[0].remediation

    def test_references_merged(self):
        findings = [
            _make_finding(source="headers", reference="https://owasp.org/xfo"),
            _make_finding(source="nuclei", reference="https://developer.mozilla.org/xfo"),
        ]
        result = deduplicate(findings)
        assert "owasp" in result[0].reference
        assert "mozilla" in result[0].reference

    def test_sorted_by_severity(self):
        findings = [
            _make_finding(title="Low issue", severity=Severity.LOW),
            _make_finding(title="Critical issue", severity=Severity.CRITICAL),
            _make_finding(title="Medium issue", severity=Severity.MEDIUM),
        ]
        result = deduplicate(findings)
        assert result[0].severity == Severity.CRITICAL
        assert result[1].severity == Severity.MEDIUM
        assert result[2].severity == Severity.LOW

    def test_empty_list(self):
        assert deduplicate([]) == []

    def test_single_finding(self):
        findings = [_make_finding()]
        result = deduplicate(findings)
        assert len(result) == 1
        assert result[0].metadata["duplicate_count"] == 1
        assert result[0].metadata["sources"] == ["headers"]

    def test_mixed_duplicates_and_unique(self):
        findings = [
            _make_finding(title="Missing HSTS", source="headers"),
            _make_finding(title="Missing HSTS", source="nuclei"),
            _make_finding(title="SQL Injection", source="sqlmap", severity=Severity.CRITICAL,
                          category=Category.INJECTION),
            _make_finding(title="Weak cipher", source="testssl", severity=Severity.MEDIUM,
                          category=Category.TLS),
        ]
        result = deduplicate(findings)
        assert len(result) == 3
        # Critical first
        assert result[0].title == "SQL Injection"
        # Then the merged HIGH finding
        hsts = [f for f in result if "HSTS" in f.title][0]
        assert hsts.metadata["duplicate_count"] == 2

    def test_metadata_merged(self):
        findings = [
            _make_finding(source="headers", metadata={"template": "hdr-001"}),
            _make_finding(source="nuclei", metadata={"template_id": "nuclei-xfo"}),
        ]
        result = deduplicate(findings)
        assert result[0].metadata["template"] == "hdr-001"
        assert result[0].metadata["template_id"] == "nuclei-xfo"
