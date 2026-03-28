"""Shared utilities for webscan."""

import os
import shutil
from datetime import datetime


def ensure_output_dir(output_dir: str) -> str:
    """Create the output directory if it doesn't exist. Returns absolute path."""
    path = os.path.abspath(output_dir)
    os.makedirs(path, exist_ok=True)
    return path


def timestamp_filename(prefix: str, ext: str = "json") -> str:
    """Generate a timestamped filename like 'webscan-2024-01-15T10-30-00.json'."""
    ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    return f"{prefix}-{ts}.{ext}"


def create_scan_dir(output_dir: str) -> str:
    """Create a timestamped sub-directory for a single scan run.

    Returns the absolute path to the created directory.
    """
    ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    scan_dir = os.path.join(os.path.abspath(output_dir), f"webscan-{ts}")
    os.makedirs(scan_dir, exist_ok=True)
    return scan_dir


def tool_available(binary: str) -> tuple[bool, str]:
    """Check if a binary is available in PATH."""
    path = shutil.which(binary)
    if path:
        return True, path
    return False, f"{binary} not found in PATH"
