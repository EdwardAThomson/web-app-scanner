"""Configuration loading for webscan.

Three-layer config merge: default.yaml -> user config -> CLI flags.
"""

import os
from copy import deepcopy
from pathlib import Path

import yaml

# Shipped default config location (relative to package)
_DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "default.yaml"

# User config location
_USER_CONFIG = Path.home() / ".config" / "webscan" / "config.yaml"


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override wins for leaf values."""
    result = deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _load_yaml(path: Path) -> dict:
    """Load a YAML file, returning empty dict if missing or invalid."""
    if not path.is_file():
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except (yaml.YAMLError, OSError):
        return {}


def build_config(
    target: str | None = None,
    output_dir: str | None = None,
    output_format: str | None = None,
    source_path: str | None = None,
    config_file: str | None = None,
    **overrides,
) -> dict:
    """Build a config dict by merging defaults -> user config -> CLI flags.

    Args:
        target: Target URL for remote scanning.
        output_dir: Output directory for reports.
        output_format: Report format (json/html/both).
        source_path: Source code path for local scanning.
        config_file: Path to a config YAML file (overrides user config location).
        **overrides: Additional key-value overrides.
    """
    # Layer 1: shipped defaults
    config = _load_yaml(_DEFAULT_CONFIG)

    # Layer 2: user config (or explicit config file)
    user_path = Path(config_file) if config_file else _USER_CONFIG
    user_config = _load_yaml(user_path)
    if user_config:
        config = _deep_merge(config, user_config)

    # Layer 3: CLI flags (only override if explicitly provided)
    cli = {}
    if target is not None:
        cli["target"] = target
    if source_path is not None:
        cli["source_path"] = source_path
    if output_dir is not None:
        cli["output_dir"] = output_dir
    if output_format is not None:
        cli["output_format"] = output_format
    cli.update(overrides)

    config = _deep_merge(config, cli)

    # Ensure these keys always exist
    config.setdefault("target", "")
    config.setdefault("source_path", "")
    config.setdefault("output_dir", "./webscan-results")
    config.setdefault("output_format", "json")
    config.setdefault("modules", {})

    return config
