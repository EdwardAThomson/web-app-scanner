"""Tests for the spider / crawler module."""

from webscan.models import Category, Severity
from webscan.modules.spider import (
    SpiderModule,
    _LinkExtractor,
    _RobotsTxt,
    _build_tree_text,
    SENSITIVE_PATH_PATTERNS,
)


def _make_module(target="https://example.com", **overrides):
    config = {"target": target, "scan_dir": "", "modules": {"spider": {}}}
    config.update(overrides)
    return SpiderModule(config)


# ---------------------------------------------------------------------------
# Link extractor
# ---------------------------------------------------------------------------


class TestLinkExtractor:
    def test_anchor_href(self):
        ext = _LinkExtractor()
        ext.feed('<a href="/about">About</a>')
        assert "/about" in ext.links

    def test_form_action(self):
        ext = _LinkExtractor()
        ext.feed('<form action="/login" method="POST"></form>')
        assert "/login" in ext.links

    def test_script_src(self):
        ext = _LinkExtractor()
        ext.feed('<script src="/js/app.js"></script>')
        assert "/js/app.js" in ext.links

    def test_img_src(self):
        ext = _LinkExtractor()
        ext.feed('<img src="/images/logo.png">')
        assert "/images/logo.png" in ext.links

    def test_link_href(self):
        ext = _LinkExtractor()
        ext.feed('<link rel="stylesheet" href="/css/style.css">')
        assert "/css/style.css" in ext.links

    def test_iframe_src(self):
        ext = _LinkExtractor()
        ext.feed('<iframe src="/embed/widget"></iframe>')
        assert "/embed/widget" in ext.links

    def test_base_href(self):
        ext = _LinkExtractor()
        ext.feed('<base href="https://cdn.example.com/">')
        assert ext.base_href == "https://cdn.example.com/"

    def test_meta_refresh(self):
        ext = _LinkExtractor()
        ext.feed('<meta http-equiv="refresh" content="0;url=/new-page">')
        assert "/new-page" in ext.links

    def test_multiple_links(self):
        ext = _LinkExtractor()
        ext.feed(
            '<a href="/a">A</a>'
            '<a href="/b">B</a>'
            '<script src="/c.js"></script>'
        )
        assert len(ext.links) == 3

    def test_empty_href_skipped(self):
        ext = _LinkExtractor()
        ext.feed('<a href="">Empty</a>')
        assert len(ext.links) == 0

    def test_object_data(self):
        ext = _LinkExtractor()
        ext.feed('<object data="/flash/game.swf"></object>')
        assert "/flash/game.swf" in ext.links


# ---------------------------------------------------------------------------
# Robots.txt parser
# ---------------------------------------------------------------------------


class TestRobotsTxt:
    def test_disallow_path(self):
        robots = _RobotsTxt("User-agent: *\nDisallow: /admin\nDisallow: /private")
        assert not robots.is_allowed("/admin")
        assert not robots.is_allowed("/admin/dashboard")
        assert not robots.is_allowed("/private")
        assert robots.is_allowed("/public")
        assert robots.is_allowed("/about")

    def test_allow_all(self):
        robots = _RobotsTxt("User-agent: *\nAllow: /")
        assert robots.is_allowed("/anything")

    def test_empty_robots(self):
        robots = _RobotsTxt("")
        assert robots.is_allowed("/anything")

    def test_webscan_specific_rules(self):
        robots = _RobotsTxt("User-agent: webscan\nDisallow: /secret")
        assert not robots.is_allowed("/secret")
        assert robots.is_allowed("/public")

    def test_ignores_other_agents(self):
        robots = _RobotsTxt("User-agent: Googlebot\nDisallow: /no-google")
        assert robots.is_allowed("/no-google")

    def test_comments_stripped(self):
        robots = _RobotsTxt("User-agent: * # all bots\nDisallow: /hidden # secret stuff")
        assert not robots.is_allowed("/hidden")

    def test_root_disallow(self):
        robots = _RobotsTxt("User-agent: *\nDisallow: /")
        assert not robots.is_allowed("/anything")
        assert not robots.is_allowed("/")


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


class TestNormalizeUrl:
    def test_strips_fragment(self):
        assert SpiderModule._normalize_url("https://example.com/page#section") == "https://example.com/page"

    def test_preserves_query(self):
        assert SpiderModule._normalize_url("https://example.com/page?q=1") == "https://example.com/page?q=1"

    def test_adds_slash_to_bare_domain(self):
        assert SpiderModule._normalize_url("https://example.com") == "https://example.com/"

    def test_preserves_path(self):
        assert SpiderModule._normalize_url("https://example.com/a/b/c") == "https://example.com/a/b/c"


# ---------------------------------------------------------------------------
# Link extraction (module-level)
# ---------------------------------------------------------------------------


class TestExtractLinks:
    def test_resolves_relative_links(self):
        module = _make_module()
        html = '<a href="/about">About</a><a href="contact">Contact</a>'
        links = module._extract_links(html, "https://example.com/pages/")
        assert "https://example.com/about" in links
        assert "https://example.com/pages/contact" in links

    def test_filters_external_links(self):
        module = _make_module()
        html = '<a href="https://other.com/page">External</a><a href="/local">Local</a>'
        links = module._extract_links(html, "https://example.com/")
        assert "https://example.com/local" in links
        assert not any("other.com" in l for l in links)

    def test_skips_javascript_links(self):
        module = _make_module()
        html = '<a href="javascript:void(0)">JS</a><a href="mailto:a@b.com">Mail</a>'
        links = module._extract_links(html, "https://example.com/")
        assert len(links) == 0

    def test_deduplicates(self):
        module = _make_module()
        html = '<a href="/page">A</a><a href="/page">B</a><a href="/page#section">C</a>'
        links = module._extract_links(html, "https://example.com/")
        assert links.count("https://example.com/page") == 1

    def test_respects_base_href(self):
        module = _make_module()
        html = '<base href="https://example.com/app/"><a href="settings">Settings</a>'
        links = module._extract_links(html, "https://example.com/")
        assert "https://example.com/app/settings" in links

    def test_skips_data_urls(self):
        module = _make_module()
        html = '<a href="data:text/html,<h1>hi</h1>">Data</a>'
        links = module._extract_links(html, "https://example.com/")
        assert len(links) == 0


# ---------------------------------------------------------------------------
# Sensitive path detection
# ---------------------------------------------------------------------------


class TestSensitivePaths:
    def test_admin_path(self):
        assert SENSITIVE_PATH_PATTERNS.search("/admin")
        assert SENSITIVE_PATH_PATTERNS.search("/admin/dashboard")
        assert SENSITIVE_PATH_PATTERNS.search("/administrator")

    def test_config_path(self):
        assert SENSITIVE_PATH_PATTERNS.search("/config")
        assert SENSITIVE_PATH_PATTERNS.search("/configuration/db")

    def test_backup_path(self):
        assert SENSITIVE_PATH_PATTERNS.search("/backup")
        assert SENSITIVE_PATH_PATTERNS.search("/site.bak")

    def test_dotfiles(self):
        assert SENSITIVE_PATH_PATTERNS.search("/.git")
        assert SENSITIVE_PATH_PATTERNS.search("/.env")
        assert SENSITIVE_PATH_PATTERNS.search("/.htaccess")

    def test_wp_admin(self):
        assert SENSITIVE_PATH_PATTERNS.search("/wp-admin")
        assert SENSITIVE_PATH_PATTERNS.search("/wp-login.php")

    def test_api_docs(self):
        assert SENSITIVE_PATH_PATTERNS.search("/swagger")
        assert SENSITIVE_PATH_PATTERNS.search("/api-docs")
        assert SENSITIVE_PATH_PATTERNS.search("/graphql")

    def test_actuator(self):
        assert SENSITIVE_PATH_PATTERNS.search("/actuator")
        assert SENSITIVE_PATH_PATTERNS.search("/actuator/health")

    def test_normal_paths_not_flagged(self):
        assert not SENSITIVE_PATH_PATTERNS.search("/about")
        assert not SENSITIVE_PATH_PATTERNS.search("/products/widget")
        assert not SENSITIVE_PATH_PATTERNS.search("/contact")
        assert not SENSITIVE_PATH_PATTERNS.search("/blog/2024/post")


# ---------------------------------------------------------------------------
# Findings generation
# ---------------------------------------------------------------------------


class TestFindings:
    def _sample_pages(self):
        return [
            {"url": "https://example.com/", "status": 200, "content_type": "text/html", "depth": 0, "parent": None, "links": []},
            {"url": "https://example.com/about", "status": 200, "content_type": "text/html", "depth": 1, "parent": "https://example.com/", "links": []},
            {"url": "https://example.com/admin", "status": 403, "content_type": "text/html", "depth": 1, "parent": "https://example.com/", "links": []},
            {"url": "https://example.com/old-page", "status": 404, "content_type": "text/html", "depth": 1, "parent": "https://example.com/", "links": []},
            {"url": "https://example.com/error", "status": 500, "content_type": "text/html", "depth": 1, "parent": "https://example.com/", "links": []},
            {"url": "https://example.com/logo.png", "status": 200, "content_type": "image/png", "depth": 1, "parent": "https://example.com/", "links": []},
        ]

    def test_summary_finding(self):
        module = _make_module()
        findings = module.parse_output(self._sample_pages(), "https://example.com")
        summary = [f for f in findings if "Spider discovered" in f.title]
        assert len(summary) == 1
        assert summary[0].severity == Severity.INFO
        assert "6 URLs" in summary[0].title

    def test_sensitive_path_finding(self):
        module = _make_module()
        findings = module.parse_output(self._sample_pages(), "https://example.com")
        sensitive = [f for f in findings if "sensitive" in f.title.lower()]
        assert len(sensitive) == 1
        assert "/admin" in sensitive[0].evidence

    def test_broken_links_finding(self):
        module = _make_module()
        findings = module.parse_output(self._sample_pages(), "https://example.com")
        broken = [f for f in findings if "broken" in f.title.lower()]
        assert len(broken) == 1
        assert "404" in broken[0].evidence

    def test_server_error_finding(self):
        module = _make_module()
        findings = module.parse_output(self._sample_pages(), "https://example.com")
        errors = [f for f in findings if "server error" in f.title.lower()]
        assert len(errors) == 1
        assert errors[0].severity == Severity.MEDIUM

    def test_auth_protected_finding(self):
        module = _make_module()
        findings = module.parse_output(self._sample_pages(), "https://example.com")
        auth = [f for f in findings if "authentication" in f.title.lower()]
        assert len(auth) == 1
        assert auth[0].category == Category.AUTH

    def test_clean_site_minimal_findings(self):
        """A clean site should only produce the summary finding."""
        pages = [
            {"url": "https://example.com/", "status": 200, "content_type": "text/html", "depth": 0, "parent": None, "links": []},
            {"url": "https://example.com/about", "status": 200, "content_type": "text/html", "depth": 1, "parent": "https://example.com/", "links": []},
        ]
        module = _make_module()
        findings = module.parse_output(pages, "https://example.com")
        assert len(findings) == 1  # just the summary
        assert findings[0].severity == Severity.INFO

    def test_401_not_in_broken_links(self):
        """401/403 should appear in auth-protected, not broken links."""
        module = _make_module()
        findings = module.parse_output(self._sample_pages(), "https://example.com")
        broken = [f for f in findings if "broken" in f.title.lower()]
        if broken:
            assert "403" not in broken[0].evidence
            assert "401" not in broken[0].evidence


# ---------------------------------------------------------------------------
# Site map tree
# ---------------------------------------------------------------------------


class TestSiteMapTree:
    def test_basic_tree(self):
        pages = [
            {"url": "https://example.com/", "status": 200},
            {"url": "https://example.com/about", "status": 200},
            {"url": "https://example.com/api/users", "status": 200},
            {"url": "https://example.com/api/products", "status": 200},
        ]
        tree = _build_tree_text(pages, "https://example.com")
        assert "https://example.com/" in tree
        assert "about" in tree
        assert "api" in tree
        assert "users" in tree
        assert "products" in tree

    def test_non_200_status_shown(self):
        pages = [
            {"url": "https://example.com/", "status": 200},
            {"url": "https://example.com/admin", "status": 403},
        ]
        tree = _build_tree_text(pages, "https://example.com")
        assert "[403]" in tree

    def test_200_status_not_shown(self):
        pages = [
            {"url": "https://example.com/", "status": 200},
            {"url": "https://example.com/about", "status": 200},
        ]
        tree = _build_tree_text(pages, "https://example.com")
        assert "[200]" not in tree

    def test_empty_pages(self):
        tree = _build_tree_text([], "https://example.com")
        assert "https://example.com/" in tree


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------


class TestModuleMetadata:
    def test_module_name(self):
        module = _make_module()
        assert module.name == "spider"

    def test_built_in(self):
        module = _make_module()
        ok, info = module.check_installed()
        assert ok is True
        assert info == "built-in"

    def test_phase_0(self):
        from webscan.modules import PARALLEL_GROUPS
        assert PARALLEL_GROUPS[0] == ["spider"]
