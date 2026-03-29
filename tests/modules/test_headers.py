"""Tests for the HTTP security headers module."""

from webscan.models import Category, Severity
from webscan.modules.headers import HeadersModule


def _make_module(target="https://example.com"):
    return HeadersModule({"target": target})


# Complete set of security headers that produces zero missing-header findings
ALL_GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
}


class TestMissingHeaders:
    def test_all_headers_missing(self):
        module = _make_module()
        findings = module.parse_output({})
        titles = [f.title for f in findings]
        assert "Missing Strict-Transport-Security header" in titles
        assert "Missing Content-Security-Policy header" in titles
        assert "Missing X-Content-Type-Options header" in titles
        assert "Missing X-Frame-Options header" in titles
        assert "Missing Referrer-Policy header" in titles
        assert "Missing Permissions-Policy header" in titles
        assert "Missing X-Permitted-Cross-Domain-Policies header" in titles
        assert "Missing Cross-Origin-Opener-Policy header" in titles
        assert "Missing Cross-Origin-Resource-Policy header" in titles

    def test_all_headers_present(self):
        module = _make_module()
        findings = module.parse_output(ALL_GOOD_HEADERS)
        assert len(findings) == 0

    def test_case_insensitive_lookup(self):
        headers = {k.lower(): v for k, v in ALL_GOOD_HEADERS.items()}
        module = _make_module()
        findings = module.parse_output(headers)
        assert len(findings) == 0

    def test_xframe_not_needed_with_csp_frame_ancestors(self):
        """X-Frame-Options can be omitted if CSP frame-ancestors is set."""
        headers = dict(ALL_GOOD_HEADERS)
        del headers["X-Frame-Options"]
        headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'self'"
        module = _make_module()
        findings = module.parse_output(headers)
        titles = [f.title for f in findings]
        assert "Missing X-Frame-Options header" not in titles


class TestHSTS:
    def test_short_max_age(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Strict-Transport-Security"] = "max-age=86400"
        module = _make_module()
        findings = module.parse_output(headers)
        hsts_findings = [f for f in findings if "max-age" in f.title.lower()]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == Severity.MEDIUM

    def test_missing_includesubdomains(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Strict-Transport-Security"] = "max-age=31536000"
        module = _make_module()
        findings = module.parse_output(headers)
        sub_findings = [f for f in findings if "includeSubDomains" in f.title]
        assert len(sub_findings) == 1

    def test_good_hsts(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        module = _make_module()
        findings = module.parse_output(headers)
        assert len(findings) == 0


class TestCSP:
    def test_unsafe_inline(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        module = _make_module()
        findings = module.parse_output(headers)
        assert any("unsafe-inline" in f.title for f in findings)

    def test_unsafe_eval(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-eval'"
        module = _make_module()
        findings = module.parse_output(headers)
        assert any("unsafe-eval" in f.title for f in findings)

    def test_wildcard_default_src(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Content-Security-Policy"] = "default-src *"
        module = _make_module()
        findings = module.parse_output(headers)
        assert any("wildcard" in f.title.lower() for f in findings)

    def test_missing_default_src_and_script_src(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Content-Security-Policy"] = "img-src 'self'"
        module = _make_module()
        findings = module.parse_output(headers)
        assert any("missing default-src and script-src" in f.title.lower() for f in findings)


class TestCORS:
    def test_wildcard_origin(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Access-Control-Allow-Origin"] = "*"
        module = _make_module()
        findings = module.parse_output(headers)
        cors_findings = [f for f in findings if "CORS" in f.title]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity == Severity.MEDIUM

    def test_wildcard_with_credentials(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Access-Control-Allow-Origin"] = "*"
        headers["Access-Control-Allow-Credentials"] = "true"
        module = _make_module()
        findings = module.parse_output(headers)
        cors_findings = [f for f in findings if "CORS" in f.title]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity == Severity.CRITICAL

    def test_specific_origin_no_finding(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Access-Control-Allow-Origin"] = "https://trusted.com"
        module = _make_module()
        findings = module.parse_output(headers)
        cors_findings = [f for f in findings if "CORS" in f.title]
        assert len(cors_findings) == 0


class TestCookies:
    def test_insecure_cookie(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Set-Cookie"] = "session=abc123; Path=/"
        module = _make_module()
        findings = module.parse_output(headers)
        cookie_findings = [f for f in findings if "session" in f.title.lower()]
        # Missing Secure, HttpOnly, and SameSite
        assert len(cookie_findings) == 3

    def test_secure_cookie(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Set-Cookie"] = "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"
        module = _make_module()
        findings = module.parse_output(headers)
        cookie_findings = [f for f in findings if "cookie" in f.title.lower()]
        assert len(cookie_findings) == 0

    def test_broad_domain_cookie(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Set-Cookie"] = "sid=abc; Domain=.example.com; Secure; HttpOnly; SameSite=Lax"
        module = _make_module()
        findings = module.parse_output(headers)
        domain_findings = [f for f in findings if "subdomain" in f.title.lower()]
        assert len(domain_findings) == 1
        assert domain_findings[0].severity == Severity.MEDIUM


class TestBanners:
    def test_server_header_disclosed(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Server"] = "Apache/2.4.41 (Ubuntu)"
        module = _make_module()
        findings = module.parse_output(headers)
        banner_findings = [f for f in findings if "Server" in f.title and "technology" in f.title]
        assert len(banner_findings) == 1

    def test_x_powered_by_disclosed(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["X-Powered-By"] = "Express"
        module = _make_module()
        findings = module.parse_output(headers)
        assert any("X-Powered-By" in f.title for f in findings)

    def test_no_banner_no_finding(self):
        module = _make_module()
        findings = module.parse_output(ALL_GOOD_HEADERS)
        banner_findings = [f for f in findings if "technology" in f.title]
        assert len(banner_findings) == 0


class TestCacheControl:
    def test_missing_cache_control(self):
        headers = dict(ALL_GOOD_HEADERS)
        del headers["Cache-Control"]
        module = _make_module()
        findings = module.parse_output(headers)
        assert any("Cache-Control" in f.title for f in findings)

    def test_cache_control_no_store(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Cache-Control"] = "no-store"
        module = _make_module()
        findings = module.parse_output(headers)
        cache_findings = [f for f in findings if "Cache-Control" in f.title or "caching" in f.title.lower()]
        assert len(cache_findings) == 0

    def test_cache_control_public(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Cache-Control"] = "public, max-age=3600"
        module = _make_module()
        findings = module.parse_output(headers)
        assert any("caching" in f.title.lower() or "cache" in f.description.lower() for f in findings)


class TestCharset:
    def test_missing_charset(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Content-Type"] = "text/html"
        module = _make_module()
        findings = module.parse_output(headers)
        assert any("charset" in f.title.lower() for f in findings)

    def test_charset_present(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Content-Type"] = "text/html; charset=utf-8"
        module = _make_module()
        findings = module.parse_output(headers)
        charset_findings = [f for f in findings if "charset" in f.title.lower()]
        assert len(charset_findings) == 0


class TestETag:
    def test_inode_style_etag(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["ETag"] = '"2a-5f-63b1c8a0"'
        module = _make_module()
        findings = module.parse_output(headers)
        assert any("ETag" in f.title for f in findings)

    def test_normal_etag_no_finding(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["ETag"] = '"W/abc123def456"'
        module = _make_module()
        findings = module.parse_output(headers)
        etag_findings = [f for f in findings if "ETag" in f.title]
        assert len(etag_findings) == 0


class TestClock:
    def test_synchronized_clock(self):
        from email.utils import formatdate
        headers = dict(ALL_GOOD_HEADERS)
        headers["Date"] = formatdate(usegmt=True)
        module = _make_module()
        findings = module.parse_output(headers)
        clock_findings = [f for f in findings if "clock" in f.title.lower()]
        assert len(clock_findings) == 0

    def test_skewed_clock(self):
        headers = dict(ALL_GOOD_HEADERS)
        headers["Date"] = "Mon, 01 Jan 2024 00:00:00 GMT"
        module = _make_module()
        findings = module.parse_output(headers)
        clock_findings = [f for f in findings if "clock" in f.title.lower()]
        assert len(clock_findings) == 1


class TestServerVersions:
    """Tests for _check_server_versions (outdated / vulnerable server software)."""

    def test_apache_cve_detected(self):
        headers = {"Server": "Apache/2.4.49"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        cve_findings = [f for f in findings if "CVE" in f.title]
        assert len(cve_findings) >= 1
        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in cve_findings)

    def test_apache_eol_detected(self):
        headers = {"Server": "Apache/2.2.34"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        eol_findings = [f for f in findings if "end-of-life" in f.title]
        assert len(eol_findings) == 1
        assert eol_findings[0].severity == Severity.HIGH

    def test_php_eol_and_cve(self):
        headers = {"X-Powered-By": "PHP/7.4.33"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        eol = [f for f in findings if "end-of-life" in f.title]
        cve = [f for f in findings if "CVE" in f.title]
        assert len(eol) == 1
        assert len(cve) >= 1

    def test_openssl_eol(self):
        headers = {"Server": "Apache/2.4.62 OpenSSL/1.1.1f"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        openssl_eol = [f for f in findings if "OpenSSL" in f.title and "end-of-life" in f.title]
        assert len(openssl_eol) == 1

    def test_nginx_outdated(self):
        """A version behind latest but with no CVE match gets a LOW outdated finding."""
        headers = {"Server": "nginx/1.27.2"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        outdated = [f for f in findings if "behind" in f.title.lower()]
        assert len(outdated) >= 1
        assert outdated[0].severity == Severity.LOW

    def test_nginx_vulnerable(self):
        headers = {"Server": "nginx/1.23.1"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        cve_findings = [f for f in findings if "CVE" in f.title and "Nginx" in f.title]
        assert len(cve_findings) >= 1

    def test_current_version_no_findings(self):
        """Latest versions should produce no version-related findings."""
        headers = {"Server": "Apache/2.4.62"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        assert len(findings) == 0

    def test_no_version_in_header(self):
        """Server header without a version number should not crash."""
        headers = {"Server": "Apache"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        assert len(findings) == 0

    def test_no_server_header(self):
        module = _make_module()
        findings = module._check_server_versions({}, "https://example.com")
        assert len(findings) == 0

    def test_express_in_x_powered_by(self):
        headers = {"X-Powered-By": "Express"}
        module = _make_module()
        # Express without a version — should not match
        findings = module._check_server_versions(headers, "https://example.com")
        express_findings = [f for f in findings if "Express" in f.title]
        assert len(express_findings) == 0

    def test_remediation_includes_verify_note(self):
        headers = {"Server": "Apache/2.4.49"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        cve_findings = [f for f in findings if "CVE" in f.title]
        assert len(cve_findings) >= 1
        assert "nvd.nist.gov" in cve_findings[0].remediation
        assert "backport" in cve_findings[0].remediation.lower()

    def test_multiple_software_in_one_header(self):
        headers = {"Server": "Apache/2.4.49 OpenSSL/1.1.1f PHP/7.4.33"}
        module = _make_module()
        findings = module._check_server_versions(headers, "https://example.com")
        sources = set()
        for f in findings:
            if "Apache" in f.title:
                sources.add("apache")
            if "OpenSSL" in f.title:
                sources.add("openssl")
            if "PHP" in f.title:
                sources.add("php")
        assert "apache" in sources
        assert "openssl" in sources
        assert "php" in sources


class TestClientLibraries:
    """Tests for _check_client_libraries (outdated / vulnerable JS libraries)."""

    def test_jquery_cve(self):
        module = _make_module()
        module._page_body = '/*! jQuery v3.3.1 */ (function() {})();'
        findings = module._check_client_libraries("https://example.com")
        jquery_cve = [f for f in findings if "jQuery" in f.title and "CVE" in f.title]
        assert len(jquery_cve) >= 1

    def test_jquery_script_src_version(self):
        module = _make_module()
        module._page_body = '<script src="/js/jquery-3.3.1.min.js"></script>'
        findings = module._check_client_libraries("https://example.com")
        jquery_findings = [f for f in findings if "jQuery" in f.title]
        assert len(jquery_findings) >= 1

    def test_jquery_current_no_findings(self):
        module = _make_module()
        module._page_body = '/*! jQuery v3.7.1 */ (function() {})();'
        findings = module._check_client_libraries("https://example.com")
        jquery_findings = [f for f in findings if "jQuery" in f.title]
        assert len(jquery_findings) == 0

    def test_angularjs_eol(self):
        module = _make_module()
        module._page_body = '<script src="/js/angular-1.8.2.min.js"></script>'
        findings = module._check_client_libraries("https://example.com")
        eol = [f for f in findings if "AngularJS" in f.title and "end-of-life" in f.title]
        assert len(eol) == 1
        assert "December 31, 2021" in eol[0].description

    def test_bootstrap_cve(self):
        module = _make_module()
        module._page_body = '/*! Bootstrap v4.1.3 */ !function() {};'
        findings = module._check_client_libraries("https://example.com")
        bs_cve = [f for f in findings if "Bootstrap" in f.title and "CVE" in f.title]
        assert len(bs_cve) >= 1

    def test_lodash_prototype_pollution(self):
        module = _make_module()
        module._page_body = '/*! lodash | v4.17.10 */'
        findings = module._check_client_libraries("https://example.com")
        lodash = [f for f in findings if "Lodash" in f.title and "CVE" in f.title]
        assert len(lodash) >= 1

    def test_momentjs_eol(self):
        module = _make_module()
        module._page_body = '<script src="/js/moment-2.29.1.min.js"></script>'
        findings = module._check_client_libraries("https://example.com")
        eol = [f for f in findings if "Moment" in f.title and "end-of-life" in f.title]
        assert len(eol) == 1
        assert "maintenance mode" in eol[0].description

    def test_no_libraries_clean_page(self):
        module = _make_module()
        module._page_body = "<html><body><p>No JS libs</p></body></html>"
        findings = module._check_client_libraries("https://example.com")
        assert len(findings) == 0

    def test_empty_body(self):
        module = _make_module()
        module._page_body = ""
        findings = module._check_client_libraries("https://example.com")
        assert len(findings) == 0

    def test_angular_ng_version_attribute(self):
        module = _make_module()
        module._page_body = '<app-root ng-version="15.2.0"></app-root>'
        findings = module._check_client_libraries("https://example.com")
        angular = [f for f in findings if "Angular" in f.title and "AngularJS" not in f.title]
        assert len(angular) >= 1  # 15.x is EOL

    def test_vue2_eol(self):
        module = _make_module()
        module._page_body = '/*! Vue.js v2.7.14 */'
        findings = module._check_client_libraries("https://example.com")
        vue_eol = [f for f in findings if "Vue" in f.title and "end-of-life" in f.title]
        assert len(vue_eol) == 1

    def test_remediation_includes_verify_note(self):
        module = _make_module()
        module._page_body = '/*! jQuery v3.3.1 */'
        findings = module._check_client_libraries("https://example.com")
        jquery = [f for f in findings if "jQuery" in f.title]
        assert len(jquery) >= 1
        assert "nvd.nist.gov" in jquery[0].remediation


class TestVersionHelpers:
    """Tests for version parsing and comparison utilities."""

    def test_parse_version(self):
        from webscan.modules.headers import _parse_version
        assert _parse_version("2.4.51") == (2, 4, 51)
        assert _parse_version("1.27.3") == (1, 27, 3)
        assert _parse_version("8.3.14") == (8, 3, 14)
        assert _parse_version("3.7") == (3, 7)
        assert _parse_version("10") == (10,)
        assert _parse_version("") == ()

    def test_parse_version_with_suffix(self):
        from webscan.modules.headers import _parse_version
        assert _parse_version("1.1.1f") == (1, 1, 1)
        assert _parse_version("2.4.51-ubuntu") == (2, 4, 51)

    def test_version_lt(self):
        from webscan.modules.headers import _version_lt
        assert _version_lt("2.4.49", "2.4.51")
        assert _version_lt("1.0.0", "2.0.0")
        assert _version_lt("3.3.1", "3.5.0")
        assert not _version_lt("2.4.51", "2.4.49")
        assert not _version_lt("2.4.51", "2.4.51")

    def test_is_eol(self):
        from webscan.modules.headers import _is_eol
        assert _is_eol("2.2.34", ["2.0.", "2.2."])
        assert _is_eol("7.4.33", ["5.", "7."])
        assert not _is_eol("2.4.51", ["2.0.", "2.2."])
        assert not _is_eol("8.3.14", ["5.", "7."])


class TestFindingMetadata:
    def test_findings_have_correct_source(self):
        module = _make_module()
        findings = module.parse_output({})
        for f in findings:
            assert f.source == "headers"

    def test_findings_have_location(self):
        module = _make_module("https://my-app.test")
        findings = module.parse_output({})
        for f in findings:
            assert f.location == "https://my-app.test"
