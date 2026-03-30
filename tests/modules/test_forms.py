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


# ---------------------------------------------------------------------------
# Template scanning (source)
# ---------------------------------------------------------------------------


class TestTemplateScanning:
    def test_scans_html_templates(self, tmp_path):
        template = tmp_path / "login.html"
        template.write_text(
            '<form method="post" action="/login">\n'
            '    <input type="text" name="password">\n'
            '    <button>Login</button>\n'
            '</form>'
        )
        module = FormsModule({"source_path": str(tmp_path)})
        findings = module._scan_templates(str(tmp_path))
        assert any("not masked" in f.title.lower() for f in findings)

    def test_scans_jsx_templates(self, tmp_path):
        template = tmp_path / "Login.jsx"
        template.write_text(
            '<form method="post" action="http://insecure.com/login">\n'
            '    <input type="password" name="password" />\n'
            '</form>'
        )
        module = FormsModule({"source_path": str(tmp_path)})
        findings = module._scan_templates(str(tmp_path))
        assert any("insecure HTTP" in f.title for f in findings)

    def test_detects_missing_csrf_in_template(self, tmp_path):
        template = tmp_path / "transfer.html"
        template.write_text(
            '<form method="post" action="/transfer">\n'
            '    <input type="text" name="amount">\n'
            '    <input type="text" name="recipient">\n'
            '    <button>Send</button>\n'
            '</form>'
        )
        module = FormsModule({"source_path": str(tmp_path)})
        findings = module._scan_templates(str(tmp_path))
        assert any("CSRF" in f.title for f in findings)

    def test_skips_non_template_files(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("def login(): pass")
        module = FormsModule({"source_path": str(tmp_path)})
        findings = module._scan_templates(str(tmp_path))
        assert len(findings) == 0

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "form.html").write_text(
            '<form method="post"><input type="text" name="password"></form>'
        )
        module = FormsModule({"source_path": str(tmp_path)})
        findings = module._scan_templates(str(tmp_path))
        assert len(findings) == 0

    def test_target_type_is_both(self):
        assert FormsModule.target_type == "both"

    def test_execute_dispatches_to_source(self, tmp_path):
        template = tmp_path / "form.html"
        template.write_text(
            '<form method="post" action="/submit">\n'
            '    <input type="text" name="amount">\n'
            '    <input type="text" name="recipient">\n'
            '    <button>Send</button>\n'
            '</form>'
        )
        module = FormsModule({
            "source_path": str(tmp_path),
            "target": "",
            "scan_dir": str(tmp_path),
        })
        findings = module.execute(str(tmp_path))
        assert any("CSRF" in f.title for f in findings)
