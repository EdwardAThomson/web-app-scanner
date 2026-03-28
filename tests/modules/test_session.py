"""Tests for the session module."""

from webscan.models import Severity
from webscan.modules.session import SessionModule, _shannon_entropy, _common_prefix


def _make_module(target="https://example.com"):
    return SessionModule({"target": target})


class TestShannonEntropy:
    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        # All unique chars should have high entropy
        e = _shannon_entropy("abcdefghijklmnop")
        assert e > 3.5

    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_binary_string(self):
        # "01010101" has entropy of 1.0 (two equally likely symbols)
        e = _shannon_entropy("01010101")
        assert abs(e - 1.0) < 0.01


class TestCommonPrefix:
    def test_common_prefix(self):
        assert _common_prefix(["abc123", "abc456", "abc789"]) == "abc"

    def test_no_prefix(self):
        assert _common_prefix(["abc", "def", "ghi"]) == ""

    def test_identical(self):
        assert _common_prefix(["same", "same", "same"]) == "same"

    def test_empty_list(self):
        assert _common_prefix([]) == ""


class TestSessionAnalysis:
    def test_low_entropy_detected(self):
        module = _make_module()
        # Simulate analysis with low-entropy session IDs
        samples = [
            {"session": {"value": "aaa111", "raw": "session=aaa111; Path=/"}},
            {"session": {"value": "aaa112", "raw": "session=aaa112; Path=/"}},
            {"session": {"value": "aaa113", "raw": "session=aaa113; Path=/"}},
        ]
        findings = module._analyze_sessions(samples, "https://example.com")
        # Should detect low entropy and/or short session ID
        assert any("entropy" in f.title.lower() or "short" in f.title.lower() for f in findings)

    def test_sequential_ids_detected(self):
        module = _make_module()
        samples = [
            {"sid": {"value": "1001", "raw": "sid=1001; Path=/"}},
            {"sid": {"value": "1002", "raw": "sid=1002; Path=/"}},
            {"sid": {"value": "1003", "raw": "sid=1003; Path=/"}},
        ]
        findings = module._analyze_sessions(samples, "https://example.com")
        sequential = [f for f in findings if "sequential" in f.title.lower()]
        assert len(sequential) == 1
        assert sequential[0].severity == Severity.CRITICAL

    def test_persistent_session_cookie(self):
        module = _make_module()
        samples = [
            {"session": {"value": "abc123", "raw": "session=abc123; Path=/; Max-Age=86400; HttpOnly"}},
            {"session": {"value": "def456", "raw": "session=def456; Path=/; Max-Age=86400; HttpOnly"}},
            {"session": {"value": "ghi789", "raw": "session=ghi789; Path=/; Max-Age=86400; HttpOnly"}},
        ]
        findings = module._analyze_sessions(samples, "https://example.com")
        persistent = [f for f in findings if "persistent" in f.title.lower()]
        assert len(persistent) == 1

    def test_common_prefix_detected(self):
        module = _make_module()
        prefix = "sessionprefix_verylongcommonpart_"
        samples = [
            {"tok": {"value": f"{prefix}a", "raw": f"tok={prefix}a; Path=/"}},
            {"tok": {"value": f"{prefix}b", "raw": f"tok={prefix}b; Path=/"}},
            {"tok": {"value": f"{prefix}c", "raw": f"tok={prefix}c; Path=/"}},
        ]
        findings = module._analyze_sessions(samples, "https://example.com")
        prefix_findings = [f for f in findings if "prefix" in f.title.lower()]
        assert len(prefix_findings) == 1

    def test_no_cookies_no_findings(self):
        module = _make_module()
        assert module._analyze_sessions([], "https://example.com") == []
