"""Tests for configuration loading."""

import yaml

from webscan.config import build_config, _deep_merge, _load_yaml


class TestDeepMerge:
    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"modules": {"testssl": {"timeout": 300, "enabled": True}}}
        override = {"modules": {"testssl": {"timeout": 600}}}
        result = _deep_merge(base, override)
        assert result["modules"]["testssl"]["timeout"] == 600
        assert result["modules"]["testssl"]["enabled"] is True

    def test_override_does_not_mutate_base(self):
        base = {"a": {"b": 1}}
        override = {"a": {"b": 2}}
        _deep_merge(base, override)
        assert base["a"]["b"] == 1


class TestBuildConfig:
    def test_defaults_loaded(self):
        config = build_config()
        assert "modules" in config
        assert config["output_dir"] == "./webscan-results"

    def test_cli_overrides(self):
        config = build_config(target="https://test.com", output_dir="/tmp/out")
        assert config["target"] == "https://test.com"
        assert config["output_dir"] == "/tmp/out"

    def test_yaml_config_file(self, tmp_path):
        cfg = tmp_path / "test.yaml"
        cfg.write_text(yaml.dump({
            "modules": {
                "testssl": {"timeout": 999},
            },
        }))
        config = build_config(config_file=str(cfg))
        assert config["modules"]["testssl"]["timeout"] == 999

    def test_cli_overrides_yaml(self, tmp_path):
        cfg = tmp_path / "test.yaml"
        cfg.write_text(yaml.dump({"output_dir": "/from/yaml"}))
        config = build_config(config_file=str(cfg), output_dir="/from/cli")
        assert config["output_dir"] == "/from/cli"

    def test_missing_yaml_graceful(self):
        config = build_config(config_file="/nonexistent/config.yaml")
        # Should still work with defaults
        assert "modules" in config

    def test_sqlmap_disabled_by_default(self):
        config = build_config()
        assert config["modules"]["sqlmap"]["enabled"] is False
