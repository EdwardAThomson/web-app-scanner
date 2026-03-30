"""Tests for the disclosure module."""

from webscan.models import Category, Severity
from webscan.modules.disclosure import DisclosureModule


def _make_module(target="https://example.com"):
    return DisclosureModule({"target": target})


class TestHTMLComments:
    def test_sensitive_comment(self):
        body = '<html><!-- TODO: fix password reset bug --><body></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        comment_findings = [f for f in findings if "comment" in f.title.lower()]
        assert len(comment_findings) == 1
        assert "todo" in comment_findings[0].description.lower()

    def test_short_comments_ignored(self):
        body = '<html><!-- hi --><body></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        assert not any("comment" in f.title.lower() for f in findings)

    def test_many_comments_flagged(self):
        comments = "\n".join(f"<!-- Comment number {i} is here for context -->" for i in range(15))
        body = f"<html>{comments}<body></body></html>"
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        assert any("15 HTML comments" in f.title for f in findings)

    def test_no_comments(self):
        body = "<html><body><p>Clean page</p></body></html>"
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        assert not any("comment" in f.title.lower() for f in findings)


class TestEmails:
    def test_email_found(self):
        body = '<html><body>Contact admin@company.com for help</body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        email_findings = [f for f in findings if "email" in f.title.lower()]
        assert len(email_findings) == 1
        assert "admin@company.com" in email_findings[0].evidence

    def test_w3_org_ignored(self):
        body = '<html xmlns="http://www.w3.org/1999/xhtml"><body></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        email_findings = [f for f in findings if "email" in f.title.lower()]
        assert len(email_findings) == 0

    def test_no_emails(self):
        body = "<html><body>No contact info here</body></html>"
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        assert not any("email" in f.title.lower() for f in findings)


class TestInternalIPs:
    def test_private_ip_in_body(self):
        body = "<html><body>Server: 192.168.1.100</body></html>"
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        ip_findings = [f for f in findings if "Internal IP" in f.title]
        assert len(ip_findings) == 1
        assert "192.168.1.100" in ip_findings[0].evidence

    def test_private_ip_in_headers(self):
        body = "<html><body>Clean</body></html>"
        headers = {"X-Backend-Server": "10.0.0.5"}
        module = _make_module()
        findings = module.parse_output(body, "https://example.com", headers)
        ip_findings = [f for f in findings if "Internal IP" in f.title]
        assert len(ip_findings) == 1

    def test_localhost_ignored(self):
        body = "<html><body>Server: 127.0.0.1</body></html>"
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        ip_findings = [f for f in findings if "Internal IP" in f.title]
        assert len(ip_findings) == 0

    def test_no_ips(self):
        body = "<html><body>Public server</body></html>"
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        assert not any("IP" in f.title for f in findings)


class TestSRI:
    def test_external_script_without_sri(self):
        body = '<html><head><script src="https://cdn.example.com/app.js"></script></head><body></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        sri_findings = [f for f in findings if "Subresource Integrity" in f.title]
        assert len(sri_findings) == 1

    def test_external_script_with_sri(self):
        body = '<html><head><script src="https://cdn.example.com/app.js" integrity="sha384-abc" crossorigin="anonymous"></script></head><body></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        sri_findings = [f for f in findings if "Subresource Integrity" in f.title and "script" in f.title.lower()]
        assert len(sri_findings) == 0

    def test_local_script_not_flagged(self):
        body = '<html><head><script src="/js/app.js"></script></head><body></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        sri_findings = [f for f in findings if "Subresource Integrity" in f.title]
        assert len(sri_findings) == 0

    def test_external_stylesheet_without_sri(self):
        body = '<html><head><link rel="stylesheet" href="https://cdn.example.com/style.css"></head><body></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        sri_findings = [f for f in findings if "Subresource Integrity" in f.title and "stylesheet" in f.title.lower()]
        assert len(sri_findings) == 1


class TestAPIKeys:
    def test_aws_access_key(self):
        body = '<html><body><script>var key = "AKIAIOSFODNN7EXAMPLE";</script></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        key_findings = [f for f in findings if "AWS Access Key" in f.title]
        assert len(key_findings) == 1
        assert key_findings[0].severity == Severity.CRITICAL
        assert key_findings[0].category == Category.SECRET
        # Should be redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in key_findings[0].evidence

    def test_github_token(self):
        body = '<html><body><script>const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";</script></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        key_findings = [f for f in findings if "GitHub Token" in f.title]
        assert len(key_findings) == 1
        assert key_findings[0].severity == Severity.CRITICAL

    def test_stripe_secret_key(self):
        fake_key = "sk_live_" + "abcdefghijklmnopqrstuvwx"
        body = f'<html><body><script>Stripe("{fake_key}");</script></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        key_findings = [f for f in findings if "Stripe Secret" in f.title]
        assert len(key_findings) == 1

    def test_google_api_key(self):
        body = '<html><body><script>var apiKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";</script></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        key_findings = [f for f in findings if "Google API Key" in f.title]
        assert len(key_findings) == 1
        assert key_findings[0].severity == Severity.HIGH

    def test_generic_secret_assignment(self):
        body = '<html><body><script>const api_key = "SuperSecretKeyValue12345678";</script></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        key_findings = [f for f in findings if "Generic Secret" in f.title]
        assert len(key_findings) == 1

    def test_private_key(self):
        body = '<html><body><pre>-----BEGIN RSA PRIVATE KEY-----\nMIIE...</pre></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        key_findings = [f for f in findings if "Private Key" in f.title]
        assert len(key_findings) == 1
        assert key_findings[0].severity == Severity.CRITICAL

    def test_no_keys_clean_page(self):
        body = '<html><body><p>No secrets here</p></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        key_findings = [f for f in findings if f.category == Category.SECRET]
        assert len(key_findings) == 0

    def test_deduplication(self):
        body = '<html><body><script>var k1 = "AKIAIOSFODNN7EXAMPLE"; var k2 = "AKIAIOSFODNN7EXAMPLE";</script></body></html>'
        module = _make_module()
        findings = module.parse_output(body, "https://example.com")
        key_findings = [f for f in findings if "AWS Access Key" in f.title]
        assert len(key_findings) == 1  # Deduplicated


# ---------------------------------------------------------------------------
# Source file scanning
# ---------------------------------------------------------------------------


class TestSourceFileScanning:
    def test_detects_api_key_in_source(self, tmp_path):
        py_file = tmp_path / "config.py"
        py_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        module = DisclosureModule({"source_path": str(tmp_path), "scan_dir": str(tmp_path)})
        findings = module._scan_source_files(str(tmp_path))
        key_findings = [f for f in findings if "AWS" in f.title]
        assert len(key_findings) == 1

    def test_detects_email_in_source(self, tmp_path):
        js_file = tmp_path / "contact.js"
        js_file.write_text('const admin = "admin@company.com";\n')
        module = DisclosureModule({"source_path": str(tmp_path), "scan_dir": str(tmp_path)})
        findings = module._scan_source_files(str(tmp_path))
        email_findings = [f for f in findings if "email" in f.title.lower()]
        assert len(email_findings) == 1

    def test_detects_internal_ip_in_source(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("database_host: 10.0.1.50\n")
        module = DisclosureModule({"source_path": str(tmp_path), "scan_dir": str(tmp_path)})
        findings = module._scan_source_files(str(tmp_path))
        ip_findings = [f for f in findings if "Internal IP" in f.title]
        assert len(ip_findings) == 1

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE";\n')
        module = DisclosureModule({"source_path": str(tmp_path), "scan_dir": str(tmp_path)})
        findings = module._scan_source_files(str(tmp_path))
        assert len(findings) == 0

    def test_skips_non_source_extensions(self, tmp_path):
        img = tmp_path / "logo.png"
        img.write_bytes(b"\x89PNG\r\n")
        module = DisclosureModule({"source_path": str(tmp_path), "scan_dir": str(tmp_path)})
        findings = module._scan_source_files(str(tmp_path))
        assert len(findings) == 0

    def test_target_type_is_both(self):
        assert DisclosureModule.target_type == "both"

    def test_execute_dispatches_to_source(self, tmp_path):
        py_file = tmp_path / "secret.py"
        py_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        module = DisclosureModule({
            "source_path": str(tmp_path),
            "target": "",
            "scan_dir": str(tmp_path),
        })
        findings = module.execute(str(tmp_path))
        assert any("AWS" in f.title for f in findings)
