"""ffuf wrapper module."""

import json
import tempfile

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule

# Default wordlist locations (common on Linux)
DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]


class FfufModule(BaseModule):
    name = "ffuf"
    tool_binary = "ffuf"
    description = "Web content and directory discovery (fuzzing)"

    def get_version(self) -> str:
        try:
            result = self.run_command([self.tool_binary, "-V"])
            return self.strip_ansi(result.stdout.strip())
        except Exception:
            return "unknown"

    def _find_wordlist(self) -> str | None:
        """Find a usable wordlist on the system."""
        import os
        mod_config = self.config.get("modules", {}).get("ffuf", {})
        configured = mod_config.get("wordlist", "")
        if configured and os.path.isfile(configured):
            return configured
        for wl in DEFAULT_WORDLISTS:
            if os.path.isfile(wl):
                return wl
        return None

    def execute(self, target: str) -> list[Finding]:
        mod_config = self.config.get("modules", {}).get("ffuf", {})
        timeout = mod_config.get("timeout", 600)

        wordlist = self._find_wordlist()
        if not wordlist:
            raise FileNotFoundError(
                "No wordlist found. Set modules.ffuf.wordlist in config or install seclists/dirb."
            )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        # Ensure target URL has FUZZ keyword
        fuzz_url = target
        if "FUZZ" not in target:
            fuzz_url = target.rstrip("/") + "/FUZZ"

        cmd = [
            self.tool_binary,
            "-u", fuzz_url,
            "-w", wordlist,
            "-of", "json",
            "-o", tmp_path,
            "-mc", "200,201,204,301,302,307,401,403",  # Match these status codes
            "-t", str(mod_config.get("threads", 40)),
            "-s",  # Silent mode (no banner)
        ]

        extensions = mod_config.get("extensions", "")
        if extensions:
            cmd.extend(["-e", extensions])

        self.run_command(cmd, timeout=timeout)

        try:
            with open(tmp_path, "r") as f:
                raw = f.read()
        except FileNotFoundError:
            raw = "{}"

        return self.parse_output(raw)

    def parse_output(self, raw_output: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        results = data.get("results", [])
        for entry in results:
            url = entry.get("url", "")
            status = entry.get("status", 0)
            length = entry.get("length", 0)
            words = entry.get("words", 0)
            input_val = entry.get("input", {}).get("FUZZ", "")
            redirect = entry.get("redirectlocation", "")

            # Determine severity based on status code
            if status in (200, 201, 204):
                severity = Severity.INFO
                desc = f"Accessible endpoint found: {url}"
            elif status in (301, 302, 307):
                severity = Severity.INFO
                desc = f"Redirect found: {url} -> {redirect}"
            elif status == 401:
                severity = Severity.LOW
                desc = f"Authentication required: {url}"
            elif status == 403:
                severity = Severity.LOW
                desc = f"Forbidden (exists but restricted): {url}"
            else:
                severity = Severity.INFO
                desc = f"Response {status} at: {url}"

            findings.append(Finding(
                title=f"[ffuf] /{input_val} ({status})",
                severity=severity,
                category=Category.FUZZING,
                source=self.name,
                description=desc,
                location=url,
                evidence=f"Status: {status}, Size: {length}, Words: {words}",
                metadata={
                    "status_code": status,
                    "content_length": length,
                    "words": words,
                    "input": input_val,
                    "redirect": redirect,
                },
            ))

        return findings
