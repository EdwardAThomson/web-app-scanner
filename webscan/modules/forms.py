"""HTML form security analysis module (pure Python).

Fetches web pages and analyzes HTML forms for:
- Autocomplete enabled on sensitive fields (passwords, credit cards)
- Password fields not masked (missing type="password")
- CSRF token presence in forms
- Login forms submitted over HTTP
- Credentials sent via GET method
"""

from html.parser import HTMLParser

from webscan.models import Category, Finding, Severity
from webscan.modules.base import BaseModule
from webscan.http_log import logged_request

# Field names that should have autocomplete="off" or autocomplete="new-password"
SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "pass", "pwd",
    "new_password", "new-password", "newpassword",
    "confirm_password", "confirm-password", "confirmpassword",
    "old_password", "old-password", "oldpassword",
    "current_password", "current-password",
    "credit_card", "credit-card", "creditcard", "cc_number", "cc-number",
    "card_number", "card-number", "cardnumber",
    "cvv", "cvc", "csv", "security_code", "security-code",
    "ssn", "social_security", "social-security",
    "pin", "secret", "token",
}

# Names that indicate a password field
PASSWORD_FIELD_NAMES = {
    "password", "passwd", "pass", "pwd",
    "new_password", "new-password", "newpassword",
    "confirm_password", "confirm-password",
    "old_password", "old-password",
    "current_password", "current-password",
}

# Common CSRF token field names
CSRF_TOKEN_NAMES = {
    "csrf_token", "csrf-token", "csrftoken",
    "_csrf", "csrf", "csrfmiddlewaretoken",
    "_token", "token", "__requestverificationtoken",
    "authenticity_token", "xsrf_token", "xsrf-token",
    "anti-csrf-token", "anticsrf",
}


class _FormParser(HTMLParser):
    """Parse HTML to extract form details."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": [],
            }

        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "type": attr_dict.get("type", "text").lower(),
                "name": attr_dict.get("name", "").lower(),
                "autocomplete": attr_dict.get("autocomplete", "").lower(),
                "id": attr_dict.get("id", "").lower(),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class FormsModule(BaseModule):
    name = "forms"
    tool_binary = ""
    description = "HTML form security analysis (autocomplete, CSRF, password masking)"

    def check_installed(self) -> tuple[bool, str]:
        return True, "built-in"

    def get_version(self) -> str:
        return "built-in"

    def execute(self, target: str) -> list[Finding]:
        body = self._fetch_page(target)
        if body is None:
            return []
        self._save_raw_output(body, "forms-raw.html")
        return self.parse_output(body, target)

    def _fetch_page(self, target: str) -> str | None:
        result = logged_request(target, module_name=self.name)
        if result is None:
            return None
        _status, body, _headers = result
        return body

    def parse_output(self, body: str, target: str = "") -> list[Finding]:
        """Analyze HTML forms in the page body."""
        findings = []

        parser = _FormParser()
        try:
            parser.feed(body)
        except Exception:
            pass

        for form in parser.forms:
            findings.extend(self._check_autocomplete(form, target))
            findings.extend(self._check_password_masking(form, target))
            findings.extend(self._check_csrf_token(form, target))
            findings.extend(self._check_form_method(form, target))
            findings.extend(self._check_form_action(form, target))

        return findings

    def _check_autocomplete(self, form: dict, target: str) -> list[Finding]:
        """Check for autocomplete on sensitive input fields."""
        findings = []

        for inp in form["inputs"]:
            name = inp["name"]
            autocomplete = inp["autocomplete"]

            if name in SENSITIVE_FIELD_NAMES and autocomplete not in ("off", "new-password", "current-password"):
                # type="password" implicitly disables autocomplete in most browsers,
                # but explicit autocomplete="off" is preferred for non-password sensitive fields
                if inp["type"] != "password" or name not in PASSWORD_FIELD_NAMES:
                    findings.append(Finding(
                        title=f"Autocomplete enabled on sensitive field '{name}'",
                        severity=Severity.MEDIUM,
                        category=Category.MISCONFIGURATION,
                        source=self.name,
                        description=f"Sensitive form field '{name}' does not have autocomplete disabled. "
                                    "Browsers may cache the submitted value.",
                        location=target,
                        evidence=f"Form action: {form['action']}, Field: {name}, Autocomplete: {autocomplete or 'not set'}",
                        remediation=f"Add autocomplete=\"off\" to the '{name}' input field",
                    ))

        return findings

    def _check_password_masking(self, form: dict, target: str) -> list[Finding]:
        """Check that password fields use type='password'."""
        findings = []

        for inp in form["inputs"]:
            name = inp["name"]
            if name in PASSWORD_FIELD_NAMES and inp["type"] != "password":
                findings.append(Finding(
                    title=f"Password field '{name}' not masked",
                    severity=Severity.MEDIUM,
                    category=Category.MISCONFIGURATION,
                    source=self.name,
                    description=f"Input field '{name}' appears to be a password field but has type='{inp['type']}' instead of type='password'",
                    location=target,
                    evidence=f"Form action: {form['action']}, Field: {name}, Type: {inp['type']}",
                    remediation=f"Set type=\"password\" on the '{name}' input field",
                ))

        return findings

    def _check_csrf_token(self, form: dict, target: str) -> list[Finding]:
        """Check if forms that modify state have CSRF tokens."""
        findings = []

        # Only check POST forms (GET forms typically don't modify state)
        if form["method"] != "POST":
            return findings

        # Check if any input looks like a CSRF token
        input_names = {inp["name"] for inp in form["inputs"]}
        has_csrf = bool(input_names & CSRF_TOKEN_NAMES)

        # Also check for hidden inputs with token-like names
        if not has_csrf:
            for inp in form["inputs"]:
                if inp["type"] == "hidden" and ("token" in inp["name"] or "csrf" in inp["name"]):
                    has_csrf = True
                    break

        if not has_csrf:
            # Determine if this looks like a meaningful form (not just a search box)
            has_password = any(inp["type"] == "password" for inp in form["inputs"])
            has_multiple_fields = len([i for i in form["inputs"] if i["type"] not in ("hidden", "submit", "button")]) > 1

            if has_password or has_multiple_fields:
                findings.append(Finding(
                    title="POST form missing CSRF token",
                    severity=Severity.MEDIUM,
                    category=Category.VULNERABILITY,
                    source=self.name,
                    description=f"A POST form (action: {form['action'] or 'self'}) does not appear to have a CSRF token",
                    location=target,
                    evidence=f"Form method: POST, Action: {form['action'] or 'self'}, Fields: {', '.join(input_names)}",
                    remediation="Add a CSRF token (hidden field) to all state-changing forms",
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ))

        return findings

    def _check_form_method(self, form: dict, target: str) -> list[Finding]:
        """Check if forms with credentials use GET method."""
        findings = []

        if form["method"] == "GET":
            has_sensitive = any(inp["name"] in SENSITIVE_FIELD_NAMES for inp in form["inputs"])
            has_password = any(inp["type"] == "password" for inp in form["inputs"])

            if has_sensitive or has_password:
                findings.append(Finding(
                    title="Sensitive form data submitted via GET",
                    severity=Severity.HIGH,
                    category=Category.VULNERABILITY,
                    source=self.name,
                    description=f"A form containing sensitive fields uses GET method. "
                                "Credentials will appear in the URL, browser history, and server logs.",
                    location=target,
                    evidence=f"Form action: {form['action']}, Method: GET",
                    remediation="Change the form method to POST",
                ))

        return findings

    def _check_form_action(self, form: dict, target: str) -> list[Finding]:
        """Check if login forms submit to HTTP (not HTTPS)."""
        findings = []
        action = form["action"]

        has_password = any(inp["type"] == "password" for inp in form["inputs"])

        if has_password and action.startswith("http://"):
            findings.append(Finding(
                title="Login form submits to insecure HTTP",
                severity=Severity.HIGH,
                category=Category.VULNERABILITY,
                source=self.name,
                description=f"A form with password fields submits to an HTTP (not HTTPS) URL: {action}",
                location=target,
                evidence=f"Form action: {action}",
                remediation="Ensure login forms submit to HTTPS URLs",
            ))

        return findings
