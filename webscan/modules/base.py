"""Abstract base class for all scanner modules."""

import os
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod

from webscan.models import Finding, ModuleResult


class BaseModule(ABC):
    """All scanner modules inherit from this."""

    name: str = ""
    tool_binary: str = ""
    description: str = ""
    target_type: str = "url"  # "url", "source", or "both"

    def __init__(self, config: dict):
        self.config = config
        self._raw_output_path = ""

    def check_installed(self) -> tuple[bool, str]:
        """Check if the external tool is available.

        Returns (is_installed, path_or_error_message).
        Pure-Python modules should override to return (True, "built-in").
        """
        if not self.tool_binary:
            return True, "built-in"
        path = shutil.which(self.tool_binary)
        if path:
            return True, path
        return False, f"{self.tool_binary} not found in PATH"

    def get_version(self) -> str:
        """Return tool version string. Override per module."""
        return "unknown"

    @staticmethod
    def strip_ansi(text: str) -> str:
        """Remove ANSI escape codes from text."""
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def run_command(
        self, cmd: list[str], timeout: int = 300, env: dict | None = None
    ) -> subprocess.CompletedProcess:
        """Run an external command and return the result."""
        import os
        run_env = None
        if env:
            run_env = {**os.environ, **env}
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=run_env,
        )

    def run(self, target: str) -> ModuleResult:
        """Execute the scan and return normalized results.

        The default implementation handles timing, error catching, and
        delegates to execute() for the actual work.
        """
        start = time.time()
        try:
            installed, info = self.check_installed()
            if not installed:
                return ModuleResult(
                    module_name=self.name,
                    success=False,
                    error=info,
                    duration_seconds=time.time() - start,
                )
            findings = self.execute(target)
            return ModuleResult(
                module_name=self.name,
                success=True,
                findings=findings,
                duration_seconds=time.time() - start,
                tool_version=self.get_version(),
                raw_output_path=self._raw_output_path,
            )
        except subprocess.TimeoutExpired:
            return ModuleResult(
                module_name=self.name,
                success=False,
                error=f"{self.name} timed out",
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            return ModuleResult(
                module_name=self.name,
                success=False,
                error=str(e),
                duration_seconds=time.time() - start,
            )

    def _save_raw_output(self, content: str, filename: str) -> str:
        """Save raw tool output to the scan directory. Returns the file path."""
        scan_dir = self.config.get("scan_dir", "")
        if not scan_dir:
            return ""
        path = os.path.join(scan_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        self._raw_output_path = path
        return path

    def _raw_file_path(self, filename: str) -> str:
        """Return a path inside scan_dir for the tool to write to directly.

        Falls back to a temp file if scan_dir is not set (e.g. in tests).
        """
        scan_dir = self.config.get("scan_dir", "")
        if scan_dir:
            path = os.path.join(scan_dir, filename)
            self._raw_output_path = path
            return path
        import tempfile
        tmp = tempfile.NamedTemporaryFile(
            suffix=os.path.splitext(filename)[1], delete=False
        )
        tmp.close()
        return tmp.name

    @abstractmethod
    def execute(self, target: str) -> list[Finding]:
        """Run the scan and return findings. Implement in subclasses."""
        ...

    @abstractmethod
    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parse raw tool output into Finding objects."""
        ...
