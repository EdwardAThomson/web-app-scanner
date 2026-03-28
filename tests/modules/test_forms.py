"""Tests for the forms module."""

from webscan.models import Severity
from webscan.modules.forms import FormsModule


def _make_module(target="https://example.com"):
    return FormsModule({"target": target})


class TestAutocomplete:
    def test_sensitive_field_without_autocomplete(self):
        body = '''<html><body>
        <form method="post" action="/pay">
            <input type="text" name="credit_card">
            <button>Pay</button>
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        auto_findings = [f for f in findings if "autocomplete" in f.title.lower()]
        assert len(auto_findings) == 1
        assert "credit_card" in auto_findings[0].evidence

    def test_password_field_not_flagged(self):
        """Password fields with type=password are typically handled by browsers."""
        body = '''<html><body>
        <form method="post" action="/login">
            <input type="text" name="username">
            <input type="password" name="password">
            <button>Login</button>
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        auto_findings = [f for f in findings if "autocomplete" in f.title.lower()]
        assert len(auto_findings) == 0

    def test_autocomplete_off_no_finding(self):
        body = '''<html><body>
        <form method="post" action="/pay">
            <input type="text" name="credit_card" autocomplete="off">
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        auto_findings = [f for f in findings if "autocomplete" in f.title.lower()]
        assert len(auto_findings) == 0


class TestPasswordMasking:
    def test_unmasked_password(self):
        body = '''<html><body>
        <form method="post" action="/login">
            <input type="text" name="password">
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        mask_findings = [f for f in findings if "not masked" in f.title.lower()]
        assert len(mask_findings) == 1

    def test_masked_password(self):
        body = '''<html><body>
        <form method="post" action="/login">
            <input type="password" name="password">
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        mask_findings = [f for f in findings if "not masked" in f.title.lower()]
        assert len(mask_findings) == 0


class TestCSRFToken:
    def test_post_form_without_csrf(self):
        body = '''<html><body>
        <form method="post" action="/transfer">
            <input type="text" name="amount">
            <input type="text" name="recipient">
            <button>Send</button>
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        csrf_findings = [f for f in findings if "CSRF" in f.title]
        assert len(csrf_findings) == 1

    def test_post_form_with_csrf(self):
        body = '''<html><body>
        <form method="post" action="/transfer">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="text" name="amount">
            <input type="text" name="recipient">
            <button>Send</button>
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        csrf_findings = [f for f in findings if "CSRF" in f.title]
        assert len(csrf_findings) == 0

    def test_get_form_not_checked(self):
        body = '''<html><body>
        <form method="get" action="/search">
            <input type="text" name="q">
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        csrf_findings = [f for f in findings if "CSRF" in f.title]
        assert len(csrf_findings) == 0


class TestFormMethod:
    def test_password_via_get(self):
        body = '''<html><body>
        <form method="get" action="/login">
            <input type="password" name="password">
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        method_findings = [f for f in findings if "GET" in f.title]
        assert len(method_findings) == 1
        assert method_findings[0].severity == Severity.HIGH

    def test_password_via_post_ok(self):
        body = '''<html><body>
        <form method="post" action="/login">
            <input type="password" name="password">
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        method_findings = [f for f in findings if "GET" in f.title and "Sensitive" in f.title]
        assert len(method_findings) == 0


class TestFormAction:
    def test_login_form_http_action(self):
        body = '''<html><body>
        <form method="post" action="http://insecure.com/login">
            <input type="password" name="password">
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        action_findings = [f for f in findings if "insecure HTTP" in f.title]
        assert len(action_findings) == 1

    def test_login_form_https_action(self):
        body = '''<html><body>
        <form method="post" action="https://secure.com/login">
            <input type="password" name="password">
        </form></body></html>'''
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        action_findings = [f for f in findings if "insecure HTTP" in f.title]
        assert len(action_findings) == 0


class TestNoForms:
    def test_empty_page(self):
        body = "<html><body><p>No forms here</p></body></html>"
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        assert len(findings) == 0
