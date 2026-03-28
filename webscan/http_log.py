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


def init_log(output_dir: str) -> str:
    """Initialize the HTTP log file. Returns the log file path."""
    global _log_file, _log_path
    out_dir = ensure_output_dir(output_dir)
    ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    _log_path = os.path.join(out_dir, f"http-log-{ts}.jsonl")
    _log_file = open(_log_path, "a")
    return _log_path


def close_log():
    """Close the HTTP log file."""
    global _log_file
    if _log_file:
        _log_file.close()
        _log_file = None


def _write_entry(entry: dict):
    """Thread-safe write of a log entry."""
    global _log_file
    if _log_file is None:
        return
    with _log_lock:
        _log_file.write(json.dumps(entry, default=str) + "\n")
        _log_file.flush()


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
