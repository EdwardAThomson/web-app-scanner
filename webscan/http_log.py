"""HTTP request/response logger.

Records all HTTP traffic from custom modules to a JSONL file for
evidence, audit, and debugging — similar in purpose to Burp's history.

Each line in the log is a JSON object with:
- timestamp, method, url, request_headers
- status, response_headers, body_preview (first 2KB)
- duration_ms, module (which module made the request)
"""

import json
import os
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from http.client import HTTPResponse
from threading import Lock

from webscan.utils import ensure_output_dir

_log_lock = Lock()
_log_file = None
_log_path = None
_readable_file = None
_readable_path = None
_request_counter = 0


def init_log(output_dir: str) -> tuple[str, str]:
    """Initialize both log files. Returns (jsonl_path, readable_path)."""
    global _log_file, _log_path, _readable_file, _readable_path, _request_counter
    out_dir = ensure_output_dir(output_dir)
    ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    _log_path = os.path.join(out_dir, f"http-log-{ts}.jsonl")
    _readable_path = os.path.join(out_dir, f"http-log-{ts}.txt")
    _log_file = open(_log_path, "a")
    _readable_file = open(_readable_path, "a")
    _request_counter = 0
    return _log_path, _readable_path


def close_log():
    """Close both log files."""
    global _log_file, _readable_file
    if _log_file:
        _log_file.close()
        _log_file = None
    if _readable_file:
        _readable_file.close()
        _readable_file = None


def _write_entry(entry: dict):
    """Thread-safe write of a log entry to both files."""
    global _log_file, _readable_file, _request_counter
    if _log_file is None:
        return
    with _log_lock:
        _log_file.write(json.dumps(entry, default=str) + "\n")
        _log_file.flush()

        if _readable_file:
            _request_counter += 1
            _readable_file.write(_format_entry(entry, _request_counter))
            _readable_file.flush()


def _format_entry(entry: dict, number: int) -> str:
    """Format a log entry as human-readable text."""
    method = entry.get("method", "GET")
    url = entry.get("url", "")
    module = entry.get("module", "")
    status = entry.get("status", 0)
    duration = entry.get("duration_ms", 0)
    ts = entry.get("timestamp", "")
    error = entry.get("error", "")

    lines = []
    lines.append(f"{'=' * 72}")
    lines.append(f"#{number}  {method} {url}")
    lines.append(f"Module: {module}  |  Status: {status}  |  {duration}ms  |  {ts}")
    lines.append("")

    req_headers = entry.get("request_headers", {})
    if req_headers:
        lines.append("Request Headers:")
        for k, v in req_headers.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    resp_headers = entry.get("response_headers", {})
    if resp_headers:
        lines.append("Response Headers:")
        for k, v in resp_headers.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    body = entry.get("body_preview", "")
    body_len = entry.get("body_length", 0)
    if body:
        lines.append(f"Body ({body_len} bytes):")
        # Indent and truncate for readability
        preview = body[:1024]
        for line in preview.splitlines():
            lines.append(f"  {line}")
        if body_len > 1024:
            lines.append(f"  ... ({body_len - 1024} more bytes)")
        lines.append("")

    if error:
        lines.append(f"Error: {error}")
        lines.append("")

    return "\n".join(lines) + "\n"


def log_entry(
    url: str,
    method: str = "GET",
    status: int = 0,
    request_headers: dict | None = None,
    response_headers: dict | None = None,
    duration_ms: int = 0,
    module_name: str = "",
    error: str = "",
):
    """Log a manually-constructed HTTP request/response entry.

    Use this when a module needs low-level HTTP access (e.g. to preserve
    duplicate headers) but still wants the traffic recorded.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": module_name,
        "method": method,
        "url": url,
        "request_headers": request_headers or {},
        "status": status,
        "response_headers": response_headers or {},
        "duration_ms": duration_ms,
    }
    if error:
        entry["error"] = error
    _write_entry(entry)


def logged_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    module_name: str = "",
    timeout: int = 30,
    body_preview_limit: int = 2048,
) -> tuple[int, str, dict[str, str]] | None:
    """Make an HTTP request and log both request and response.

    Returns (status_code, body, response_headers) or None on connection error.
    """
    req_headers = {"User-Agent": "webscan/0.1.0"}
    if headers:
        req_headers.update(headers)

    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method=method, headers=req_headers)

    start = time.time()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": module_name,
        "method": method,
        "url": url,
        "request_headers": req_headers,
    }

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            resp: HTTPResponse
            body = resp.read().decode("utf-8", errors="replace")
            duration_ms = int((time.time() - start) * 1000)
            resp_headers = dict(resp.headers)

            entry.update({
                "status": resp.status,
                "response_headers": resp_headers,
                "body_preview": body[:body_preview_limit],
                "body_length": len(body),
                "duration_ms": duration_ms,
            })
            _write_entry(entry)
            return resp.status, body, resp_headers

    except urllib.error.HTTPError as e:
        duration_ms = int((time.time() - start) * 1000)
        entry.update({
            "status": e.code,
            "response_headers": dict(e.headers) if e.headers else {},
            "body_preview": "",
            "body_length": 0,
            "duration_ms": duration_ms,
            "error": str(e),
        })
        _write_entry(entry)
        return e.code, "", dict(e.headers) if e.headers else {}

    except (urllib.error.URLError, OSError) as e:
        duration_ms = int((time.time() - start) * 1000)
        entry.update({
            "status": 0,
            "duration_ms": duration_ms,
            "error": str(e),
        })
        _write_entry(entry)
        return None
