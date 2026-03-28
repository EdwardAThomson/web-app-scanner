"""Security testing checklist data model.

Maps every checklist item to the webscan module(s) that cover it,
the coverage level, severity, and status (active/deprecated/manual).

"""

from dataclasses import dataclass, field
from enum import Enum


class Coverage(str, Enum):
    AUTOMATED = "automated"
    PARTIAL = "partial"
    MANUAL = "manual"
    NOT_COVERED = "not_covered"


class ItemStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    LEGACY = "legacy"


@dataclass
class ChecklistItem:
    id: str
    title: str
    category: str
    severity: int  # 1-4 scale (4=critical, 3=high, 2=medium, 1=low), 0=info
    modules: list[str] = field(default_factory=list)
    coverage: Coverage = Coverage.NOT_COVERED
    status: ItemStatus = ItemStatus.ACTIVE
    notes: str = ""


# ---------------------------------------------------------------------------
# The checklist
# ---------------------------------------------------------------------------

CHECKLIST: list[ChecklistItem] = [

    # === Cookie Issues ===
    ChecklistItem("COOKIE-001", "Cookies accessible by all subdomains", "Cookie Issues", 3,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("COOKIE-002", "HTTPOnly flag missing on cookies", "Cookie Issues", 3,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("COOKIE-003", "Secure flag missing on cookies", "Cookie Issues", 3,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("COOKIE-004", "SameSite attribute missing on cookies", "Cookie Issues", 2,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("COOKIE-005", "Cookie regulation / GDPR consent compliance", "Cookie Issues", 1,
                  [], Coverage.MANUAL, notes="Requires manual review of consent mechanisms"),

    # === Header Issues ===
    ChecklistItem("HDR-001", "HSTS not enabled", "Header Issues", 3,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-002", "Content Security Policy (CSP) not set", "Header Issues", 2,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-003", "X-Frame-Options / CSP frame-ancestors missing (clickjacking)", "Header Issues", 3,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-004", "X-Content-Type-Options missing", "Header Issues", 1,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-005", "Referrer-Policy not set", "Header Issues", 1,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-006", "Permissions-Policy not set", "Header Issues", 1,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-007", "CORS misconfiguration", "Header Issues", 3,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-008", "Cache-Control missing or permissive", "Header Issues", 3,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-009", "Host header poisoning", "Header Issues", 3,
                  ["nuclei"], Coverage.PARTIAL, notes="Nuclei templates; custom check or ZAP for comprehensive testing"),
    ChecklistItem("HDR-010", "X-Permitted-Cross-Domain-Policies missing", "Header Issues", 1,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-011", "Cross-Origin-Opener-Policy (COOP) missing", "Header Issues", 1,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-012", "Cross-Origin-Resource-Policy (CORP) missing", "Header Issues", 1,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("HDR-013", "ETag information disclosure (inode leak)", "Header Issues", 2,
                  ["headers", "nikto"], Coverage.AUTOMATED),
    ChecklistItem("HDR-014", "HPKP not enabled", "Header Issues", 0,
                  [], Coverage.NOT_COVERED, ItemStatus.DEPRECATED,
                  notes="HPKP deprecated 2018, removed from all browsers"),
    ChecklistItem("HDR-015", "X-XSS-Protection missing", "Header Issues", 0,
                  [], Coverage.NOT_COVERED, ItemStatus.DEPRECATED,
                  notes="XSS Auditor removed from all browsers by 2020; CSP supersedes"),

    # === Information Disclosure ===
    ChecklistItem("DISC-001", "Credentials in source code / git history", "Information Disclosure", 4,
                  ["gitleaks", "trivy"], Coverage.AUTOMATED,
                  notes="gitleaks scans git history; trivy detects secrets in files"),
    ChecklistItem("DISC-001b", "API keys / secrets exposed in live pages or JavaScript", "Information Disclosure", 4,
                  ["disclosure"], Coverage.AUTOMATED,
                  notes="Scans page HTML and linked JS files for AWS, Stripe, GitHub, Google, Slack keys and more"),
    ChecklistItem("DISC-002", "Verbose error messages", "Information Disclosure", 3,
                  ["nikto", "nuclei"], Coverage.PARTIAL, notes="ZAP for triggered errors"),
    ChecklistItem("DISC-003", "Server technology disclosed via headers", "Information Disclosure", 3,
                  ["headers", "nikto"], Coverage.AUTOMATED),
    ChecklistItem("DISC-004", "Information in HTML comments", "Information Disclosure", 3,
                  ["disclosure"], Coverage.AUTOMATED),
    ChecklistItem("DISC-005", "robots.txt discloses sensitive paths", "Information Disclosure", 3,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("DISC-006", "Internal filesystem path disclosure", "Information Disclosure", 3,
                  ["nuclei", "semgrep"], Coverage.PARTIAL),
    ChecklistItem("DISC-007", "Email addresses disclosed", "Information Disclosure", 3,
                  ["disclosure"], Coverage.AUTOMATED),
    ChecklistItem("DISC-008", "Internal IP address disclosed", "Information Disclosure", 3,
                  ["disclosure", "nuclei"], Coverage.AUTOMATED),
    ChecklistItem("DISC-009", "Sensitive data in browser client storage", "Information Disclosure", 3,
                  [], Coverage.MANUAL, notes="Requires headless browser / ZAP"),
    ChecklistItem("DISC-010", "EXIF metadata disclosure in files", "Information Disclosure", 1,
                  ["disclosure"], Coverage.AUTOMATED),
    ChecklistItem("DISC-011", "security.txt missing", "Information Disclosure", 0,
                  ["headers"], Coverage.AUTOMATED),

    # === Out of Date Software ===
    ChecklistItem("PATCH-001", "Vulnerable software / dependencies installed", "Out of Date Software", 4,
                  ["trivy", "nuclei", "nikto"], Coverage.AUTOMATED),
    ChecklistItem("PATCH-002", "Vulnerable framework version", "Out of Date Software", 4,
                  ["trivy", "nuclei"], Coverage.PARTIAL),

    # === General Issues ===
    ChecklistItem("GEN-001", "File inclusion (LFI/RFI)", "General Issues", 4,
                  ["nuclei", "semgrep"], Coverage.PARTIAL, notes="ZAP for dynamic testing"),
    ChecklistItem("GEN-002", "WebDAV extensions enabled", "General Issues", 4,
                  ["nikto", "nuclei"], Coverage.AUTOMATED),
    ChecklistItem("GEN-003", "Dangerous HTTP methods allowed", "General Issues", 4,
                  ["nikto", "nuclei"], Coverage.AUTOMATED),
    ChecklistItem("GEN-004", "GDPR / data protection compliance", "General Issues", 4,
                  [], Coverage.MANUAL, notes="Legal and organizational assessment"),
    ChecklistItem("GEN-005", "Available over unencrypted channel", "General Issues", 3,
                  ["testssl", "headers"], Coverage.AUTOMATED),
    ChecklistItem("GEN-006", "Backup files accessible", "General Issues", 3,
                  ["ffuf", "nikto", "nuclei"], Coverage.AUTOMATED),
    ChecklistItem("GEN-007", "Directory indexing enabled", "General Issues", 3,
                  ["nikto", "nuclei", "ffuf"], Coverage.AUTOMATED),
    ChecklistItem("GEN-008", "Directory traversal vulnerability", "General Issues", 3,
                  ["nuclei", "semgrep"], Coverage.PARTIAL, notes="ZAP for dynamic testing"),
    ChecklistItem("GEN-009", "Third-party CDN includes without SRI", "General Issues", 3,
                  ["disclosure"], Coverage.PARTIAL, notes="SRI check in disclosure module"),
    ChecklistItem("GEN-010", "Default server content", "General Issues", 3,
                  ["nikto", "nuclei"], Coverage.AUTOMATED),
    ChecklistItem("GEN-011", "crossdomain.xml overly permissive", "General Issues", 3,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("GEN-012", "Content-Type missing charset", "General Issues", 1,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("GEN-013", "No custom error pages", "General Issues", 1,
                  ["nikto"], Coverage.PARTIAL),
    ChecklistItem("GEN-014", "GET/POST methods interchangeable", "General Issues", 1,
                  ["api_routes"], Coverage.PARTIAL, notes="Extend api_routes to test method swapping"),
    ChecklistItem("GEN-015", "Server clock not synchronised", "General Issues", 1,
                  ["headers"], Coverage.AUTOMATED),
    ChecklistItem("GEN-016", "Webserver runs as root", "General Issues", 3,
                  [], Coverage.MANUAL, notes="Requires server access (Lynis)"),
    ChecklistItem("GEN-017", "Relative Path Overwrite (RPO)", "General Issues", 2,
                  [], Coverage.MANUAL, notes="Requires dynamic testing with path manipulation. ZAP or custom module"),
    ChecklistItem("GEN-018", "Incorrectly states Content-Type", "General Issues", 2,
                  [], Coverage.MANUAL, notes="Compare declared Content-Type with actual content"),
    ChecklistItem("GEN-019", "Contains unnecessary content", "General Issues", 1,
                  [], Coverage.MANUAL, notes="Requires human judgment about what is unnecessary"),
    ChecklistItem("GEN-020", "NTLM authentication supported", "General Issues", 3,
                  ["nuclei"], Coverage.PARTIAL, notes="Nuclei can detect NTLM. Legacy authentication protocol"),

    # === Forms ===
    ChecklistItem("FORM-001", "Autocomplete enabled on sensitive fields", "Forms", 3,
                  ["forms"], Coverage.AUTOMATED),
    ChecklistItem("FORM-002", "CAPTCHA bypass", "Forms", 3,
                  [], Coverage.MANUAL),
    ChecklistItem("FORM-003", "No anti-automation / rate limiting", "Forms", 1,
                  [], Coverage.MANUAL, notes="Partially detectable via repeated requests"),

    # === Injections ===
    ChecklistItem("INJ-001", "SQL injection", "Injections", 4,
                  ["sqlmap", "nuclei", "semgrep"], Coverage.AUTOMATED),
    ChecklistItem("INJ-002", "Blind SQL injection", "Injections", 4,
                  ["sqlmap"], Coverage.AUTOMATED),
    ChecklistItem("INJ-003", "Command execution / injection", "Injections", 4,
                  ["nuclei", "semgrep"], Coverage.PARTIAL, notes="ZAP for dynamic testing"),
    ChecklistItem("INJ-004", "XML External Entity (XXE)", "Injections", 4,
                  ["nuclei", "semgrep"], Coverage.PARTIAL),
    ChecklistItem("INJ-005", "Server-Side Includes injection", "Injections", 4,
                  ["nuclei"], Coverage.PARTIAL),
    ChecklistItem("INJ-006", "Reflected Cross-Site Scripting (XSS)", "Injections", 3,
                  ["nuclei"], Coverage.PARTIAL, notes="ZAP for comprehensive testing"),
    ChecklistItem("INJ-007", "Stored Cross-Site Scripting (XSS)", "Injections", 3,
                  ["nuclei"], Coverage.PARTIAL, notes="ZAP for comprehensive testing"),
    ChecklistItem("INJ-008", "DOM-Based Cross-Site Scripting (XSS)", "Injections", 3,
                  ["semgrep"], Coverage.PARTIAL, notes="ZAP with headless browser"),
    ChecklistItem("INJ-009", "XML injection", "Injections", 3,
                  ["nuclei", "semgrep"], Coverage.PARTIAL),
    ChecklistItem("INJ-010", "Email injection / header injection", "Injections", 3,
                  ["semgrep"], Coverage.PARTIAL),
    ChecklistItem("INJ-011", "Input validation flaws", "Injections", 3,
                  ["semgrep"], Coverage.PARTIAL),
    ChecklistItem("INJ-012", "Excel formula injection (CSV injection)", "Injections", 3,
                  ["semgrep"], Coverage.PARTIAL),
    ChecklistItem("INJ-013", "XPath injection", "Injections", 3,
                  ["nuclei", "semgrep"], Coverage.PARTIAL),
    ChecklistItem("INJ-014", "HTML injection", "Injections", 2,
                  ["nuclei"], Coverage.PARTIAL, notes="ZAP for dynamic testing"),
    ChecklistItem("INJ-014b", "SQL wildcards abuse", "Injections", 3,
                  [], Coverage.MANUAL, notes="Specific LIKE clause abuse testing. Manual or custom sqlmap configuration"),
    ChecklistItem("INJ-014c", "Direct control over SQL queries", "Injections", 3,
                  ["semgrep"], Coverage.PARTIAL, notes="Semgrep detects string concatenation in SQL. Runtime needs sqlmap/ZAP"),
    ChecklistItem("INJ-014d", "Null character injection", "Injections", 2,
                  [], Coverage.MANUAL, notes="Requires custom fuzzing with null bytes. ZAP fuzzer"),
    ChecklistItem("INJ-014e", "Static text injection", "Injections", 2,
                  [], Coverage.MANUAL, notes="Requires manual testing of user input reflection"),

    # === Modern additions: Injections ===
    ChecklistItem("INJ-015", "Server-Side Request Forgery (SSRF)", "Injections", 4,
                  ["nuclei", "semgrep"], Coverage.PARTIAL, notes="OWASP Top 10 2021 A10"),
    ChecklistItem("INJ-016", "Insecure deserialization", "Injections", 4,
                  ["semgrep"], Coverage.PARTIAL),
    ChecklistItem("INJ-017", "Prototype pollution (JavaScript)", "Injections", 3,
                  ["semgrep"], Coverage.PARTIAL),
    ChecklistItem("INJ-018", "HTTP request smuggling", "Injections", 4,
                  ["nuclei"], Coverage.PARTIAL),
    ChecklistItem("INJ-019", "Open redirect", "Injections", 2,
                  ["nuclei"], Coverage.PARTIAL),

    # === Age and Location Restrictions ===
    ChecklistItem("AGE-001", "Age and location verification bypass", "Age and Location Restrictions", 3,
                  [], Coverage.MANUAL, notes="Application-logic dependent. Test if client-side controls can be bypassed"),
    ChecklistItem("AGE-002", "Age verification bypass (client-side)", "Age and Location Restrictions", 3,
                  [], Coverage.MANUAL, notes="Test if age gate can be bypassed with JS blocker"),

    # === File Upload Issues ===
    ChecklistItem("UPLOAD-001", "Arbitrary file uploads", "File Upload Issues", 4,
                  ["nuclei", "semgrep"], Coverage.PARTIAL, notes="ZAP for dynamic testing"),
    ChecklistItem("UPLOAD-002", "File upload without malware protection", "File Upload Issues", 3,
                  [], Coverage.MANUAL),

    # === Session Issues ===
    ChecklistItem("SESS-001", "Session fixation", "Session Issues", 3,
                  ["session"], Coverage.PARTIAL, notes="Checks cookie attributes; full test needs ZAP"),
    ChecklistItem("SESS-002", "Session not terminated on browser close", "Session Issues", 3,
                  ["session"], Coverage.AUTOMATED, notes="Checks for persistent vs session cookies"),
    ChecklistItem("SESS-003", "Sessions not expired on logout", "Session Issues", 3,
                  [], Coverage.MANUAL, notes="Requires authenticated testing"),
    ChecklistItem("SESS-004", "No session timeout configured", "Session Issues", 3,
                  [], Coverage.MANUAL, notes="Requires long-running authenticated test"),
    ChecklistItem("SESS-005", "No account lockout policy", "Session Issues", 3,
                  [], Coverage.MANUAL, notes="Custom rate-limit probing module could partially detect"),
    ChecklistItem("SESS-006", "Non-random session IDs", "Session Issues", 3,
                  ["session"], Coverage.AUTOMATED, notes="Entropy analysis of collected session IDs"),
    ChecklistItem("SESS-007", "Session ID passed in URL", "Session Issues", 3,
                  ["semgrep", "nuclei"], Coverage.PARTIAL),
    ChecklistItem("SESS-008", "Application switches between HTTP and HTTPS", "Session Issues", 3,
                  ["testssl", "headers"], Coverage.PARTIAL),
    ChecklistItem("SESS-009", "Users unable to logout (no logout function)", "Session Issues", 2,
                  [], Coverage.MANUAL, notes="Check for presence of logout button/link"),
    ChecklistItem("SESS-010", "DoS via account lockout", "Session Issues", 3,
                  [], Coverage.MANUAL, notes="Test if lockout mechanism can be abused for denial of service"),

    # === Authentication Issues ===
    ChecklistItem("AUTH-001", "Authentication bypass", "Authentication Issues", 4,
                  ["api_routes", "nuclei"], Coverage.PARTIAL, notes="ZAP with auth contexts"),
    ChecklistItem("AUTH-002", "Weak access control / unauth access to protected content", "Authentication Issues", 3,
                  ["api_routes"], Coverage.PARTIAL),
    ChecklistItem("AUTH-003", "Admin login page publicly exposed", "Authentication Issues", 3,
                  ["ffuf", "nikto", "nuclei"], Coverage.AUTOMATED),
    ChecklistItem("AUTH-004", "User enumeration (login/register/reset)", "Authentication Issues", 3,
                  [], Coverage.MANUAL, notes="ZAP or custom module"),
    ChecklistItem("AUTH-005", "Login form over insecure channel", "Authentication Issues", 2,
                  ["forms"], Coverage.AUTOMATED),
    ChecklistItem("AUTH-006", "Sensitive information stored in cookies", "Authentication Issues", 2,
                  ["session"], Coverage.PARTIAL),
    ChecklistItem("AUTH-010", "Concurrent logins allowed", "Authentication Issues", 1,
                  [], Coverage.MANUAL, notes="Test logging in on multiple devices with same account"),
    ChecklistItem("AUTH-011", "Username not case-sensitive", "Authentication Issues", 1,
                  [], Coverage.MANUAL, notes="Test login with different casing of username"),
    ChecklistItem("AUTH-012", "Does not display last successful/unsuccessful login", "Authentication Issues", 1,
                  [], Coverage.MANUAL, notes="Check for login history display after authentication"),
    ChecklistItem("AUTH-013", "Does not display secure use policy", "Authentication Issues", 1,
                  [], Coverage.MANUAL, notes="Check for security policy/terms display"),

    # === Modern additions: Authentication ===
    ChecklistItem("AUTH-007", "JWT implementation flaws", "Authentication Issues", 4,
                  [], Coverage.NOT_COVERED, notes="Phase 4: jwt module"),
    ChecklistItem("AUTH-008", "Broken Object Level Authorization (BOLA/IDOR)", "Authentication Issues", 4,
                  [], Coverage.MANUAL, notes="ZAP with multi-user auth contexts"),
    ChecklistItem("AUTH-009", "Mass assignment / parameter pollution", "Authentication Issues", 3,
                  ["semgrep"], Coverage.PARTIAL),

    # === Password Issues ===
    ChecklistItem("PASS-001", "Weak password policy", "Password Issues", 3,
                  [], Coverage.MANUAL),
    ChecklistItem("PASS-002", "Default / weak credentials in use", "Password Issues", 3,
                  ["nuclei"], Coverage.PARTIAL),
    ChecklistItem("PASS-003", "Login credentials sent via GET", "Password Issues", 3,
                  ["forms", "semgrep"], Coverage.PARTIAL),
    ChecklistItem("PASS-004", "Password fields not masked", "Password Issues", 3,
                  ["forms"], Coverage.AUTOMATED),
    ChecklistItem("PASS-005", "Insecure forgotten password functionality", "Password Issues", 3,
                  [], Coverage.MANUAL),
    ChecklistItem("PASS-006", "Passwords stored in plaintext (source-level)", "Password Issues", 3,
                  ["semgrep"], Coverage.PARTIAL),
    ChecklistItem("PASS-007", "200 response after password submission instead of 302", "Password Issues", 3,
                  ["forms"], Coverage.PARTIAL, notes="Check if login form response allows caching of credentials"),
    ChecklistItem("PASS-008", "No forced password change on first login", "Password Issues", 3,
                  [], Coverage.MANUAL),
    ChecklistItem("PASS-009", "Passwords not case-sensitive", "Password Issues", 2,
                  [], Coverage.MANUAL, notes="Test login with different password casing"),
    ChecklistItem("PASS-010", "Authenticate with only fragment of password", "Password Issues", 2,
                  [], Coverage.MANUAL, notes="Test if partial password is accepted"),
    ChecklistItem("PASS-011", "Remember Me feature", "Password Issues", 2,
                  [], Coverage.MANUAL, notes="Review persistence token implementation and duration"),
    ChecklistItem("PASS-012", "Users unable to change password", "Password Issues", 2,
                  [], Coverage.MANUAL, notes="Test password change functionality"),
    ChecklistItem("PASS-013", "Vulnerable to keystroke logging attacks", "Password Issues", 2,
                  [], Coverage.MANUAL, notes="For financial apps — check for virtual keyboard or drop-down PIN entry"),
    ChecklistItem("PASS-014", "Security questions can be blank", "Password Issues", 2,
                  [], Coverage.MANUAL, notes="Test submitting blank security answers"),
    ChecklistItem("PASS-015", "Weak memorable customer data enforcement", "Password Issues", 2,
                  [], Coverage.MANUAL, notes="Test with weak security answers"),
    ChecklistItem("PASS-016", "Inadequate password history", "Password Issues", 1,
                  [], Coverage.MANUAL, notes="Test if previous passwords can be reused immediately"),

    # === CSRF Issues ===
    ChecklistItem("CSRF-001", "Cross-Site Request Forgery (CSRF)", "CSRF Issues", 3,
                  ["forms", "nuclei", "semgrep"], Coverage.PARTIAL, notes="ZAP for comprehensive testing"),
    ChecklistItem("CSRF-002", "CSRF token passed in URL", "CSRF Issues", 3,
                  ["semgrep"], Coverage.PARTIAL),
    ChecklistItem("CSRF-003", "CSRF token not dynamic / replayable", "CSRF Issues", 2,
                  [], Coverage.MANUAL, notes="ZAP or custom module"),

    # === Privilege Escalation ===
    ChecklistItem("PRIV-001", "Horizontal/vertical privilege escalation", "Privilege Escalation", 3,
                  ["api_routes"], Coverage.PARTIAL, notes="ZAP with multi-user auth contexts"),

    # === SSL/TLS ===
    ChecklistItem("TLS-001", "Outdated TLS protocol versions (SSLv2/3, TLS 1.0/1.1)", "SSL/TLS Issues", 3,
                  ["testssl"], Coverage.AUTOMATED),
    ChecklistItem("TLS-002", "Weak cipher suites", "SSL/TLS Issues", 3,
                  ["testssl"], Coverage.AUTOMATED),
    ChecklistItem("TLS-003", "Forward secrecy not supported/mandated", "SSL/TLS Issues", 2,
                  ["testssl"], Coverage.AUTOMATED),
    ChecklistItem("TLS-004", "Certificate issues (expired, untrusted, weak hash, key size, CN mismatch)", "SSL/TLS Issues", 3,
                  ["testssl"], Coverage.AUTOMATED),
    ChecklistItem("TLS-005", "Known TLS vulnerabilities (POODLE, BEAST, etc.)", "SSL/TLS Issues", 3,
                  ["testssl"], Coverage.AUTOMATED),

    # === Modern additions: Supply Chain ===
    ChecklistItem("SUPPLY-001", "Vulnerable dependencies (known CVEs)", "Supply Chain", 4,
                  ["trivy", "deps"], Coverage.AUTOMATED,
                  notes="Trivy scans all dependency types; deps module runs npm audit"),
    ChecklistItem("SUPPLY-002", "Dependency confusion / typosquatting", "Supply Chain", 4,
                  ["deps"], Coverage.AUTOMATED,
                  notes="deps module compares package names against popular packages using edit distance"),
    ChecklistItem("SUPPLY-003", "Subresource Integrity (SRI) missing on CDN resources", "Supply Chain", 2,
                  ["disclosure"], Coverage.AUTOMATED),
    ChecklistItem("SUPPLY-004", "Dependencies with lifecycle scripts (postinstall hooks)", "Supply Chain", 3,
                  ["deps"], Coverage.AUTOMATED,
                  notes="Checks both project package.json and installed dependency package.json files"),
    ChecklistItem("SUPPLY-005", "Low-popularity packages (potential attack vector)", "Supply Chain", 3,
                  ["deps"], Coverage.AUTOMATED,
                  notes="Flags packages with <1000 weekly npm downloads"),
    ChecklistItem("SUPPLY-006", "Suspicious code patterns in dependencies", "Supply Chain", 4,
                  ["deps"], Coverage.AUTOMATED,
                  notes="Scans node_modules for env reads, homedir access, eval, base64, SSH keys, suspicious TLDs"),

    # === Modern additions: API ===
    ChecklistItem("API-001", "GraphQL introspection enabled in production", "API Security", 3,
                  [], Coverage.NOT_COVERED, notes="Phase 4: graphql module"),
    ChecklistItem("API-002", "API rate limiting missing", "API Security", 3,
                  [], Coverage.MANUAL, notes="Partially detectable via repeated requests"),
    ChecklistItem("API-003", "Subdomain takeover", "API Security", 3,
                  ["nuclei"], Coverage.PARTIAL),
    ChecklistItem("API-004", "Excessive data exposure in API responses", "API Security", 3,
                  ["semgrep"], Coverage.PARTIAL,
                  notes="OWASP API Top 10 #3. Semgrep detects some patterns; manual review of API responses needed"),
    ChecklistItem("API-005", "Broken function-level authorization", "API Security", 4,
                  ["api_routes"], Coverage.PARTIAL,
                  notes="OWASP API Top 10 #5. api_routes tests unauth access; role-based testing needs ZAP with auth contexts"),

    # === Modern additions: Injections (additional) ===
    ChecklistItem("INJ-020", "Server-Side Template Injection (SSTI)", "Injections", 4,
                  ["nuclei", "semgrep"], Coverage.PARTIAL,
                  notes="Nuclei has SSTI templates. Semgrep detects unsafe template rendering in Jinja2, Handlebars, ERB"),
    ChecklistItem("INJ-021", "Content injection via PDF generation (SSRF/XSS in PDF renderers)", "Injections", 3,
                  ["semgrep"], Coverage.PARTIAL,
                  notes="Semgrep detects wkhtmltopdf/Puppeteer URL injection patterns. Manual testing needed for runtime"),

    # === Modern additions: Protocol / Transport ===
    ChecklistItem("PROTO-001", "HTTP/2 request smuggling (H2 desync)", "Protocol Issues", 4,
                  ["nuclei"], Coverage.PARTIAL,
                  notes="Nuclei has H2 smuggling templates. Specialized testing with tools like h2csmuggler"),
    ChecklistItem("PROTO-002", "WebSocket hijacking (CSWSH)", "Protocol Issues", 3,
                  [], Coverage.NOT_COVERED,
                  notes="Cross-Site WebSocket Hijacking. Requires checking Origin validation on WS endpoints. Phase 4 or ZAP"),
    ChecklistItem("PROTO-003", "DNS rebinding", "Protocol Issues", 3,
                  [], Coverage.MANUAL,
                  notes="Relevant for apps that trust Host header or connect to user-supplied URLs"),

    # === Modern additions: Authorization ===
    ChecklistItem("AUTHZ-001", "Insecure Direct Object References (IDOR) on file/resource access", "Authorization", 4,
                  [], Coverage.MANUAL,
                  notes="Distinct from BOLA. Test by manipulating IDs in file download, export, and resource URLs"),
    ChecklistItem("AUTHZ-002", "CORS with reflected Origin (non-wildcard bypass)", "Authorization", 3,
                  ["headers"], Coverage.PARTIAL,
                  notes="Headers module checks wildcard CORS; reflected Origin requires sending requests with different Origin headers"),

    # === Modern additions: OAuth / Identity ===
    ChecklistItem("OAUTH-001", "OAuth/OIDC open redirect in callback", "OAuth / Identity", 3,
                  ["semgrep"], Coverage.PARTIAL,
                  notes="Semgrep detects some redirect validation patterns. Manual testing of redirect_uri parameter needed"),
    ChecklistItem("OAUTH-002", "OAuth state parameter missing (CSRF in OAuth flow)", "OAuth / Identity", 3,
                  ["semgrep"], Coverage.PARTIAL,
                  notes="Semgrep detects missing state validation. Manual testing of OAuth flow needed"),
    ChecklistItem("OAUTH-003", "OAuth token leakage (via Referer, logs, URL)", "OAuth / Identity", 3,
                  ["semgrep"], Coverage.PARTIAL,
                  notes="Semgrep detects token-in-URL patterns. Referrer-Policy header (checked by headers module) mitigates Referer leakage"),

    # === Modern additions: Logic / Race Conditions ===
    ChecklistItem("LOGIC-001", "Race conditions / TOCTOU (double-spend, coupon reuse)", "Business Logic", 3,
                  [], Coverage.MANUAL,
                  notes="Requires parallel request testing. Turbo Intruder (Burp) or custom scripts"),
]


def get_checklist() -> list[ChecklistItem]:
    """Return the full checklist."""
    return CHECKLIST


def get_active_items() -> list[ChecklistItem]:
    """Return only active (non-deprecated) checklist items."""
    return [item for item in CHECKLIST if item.status == ItemStatus.ACTIVE]


# Mapping from checklist item ID to search phrases that indicate a finding.
# If any phrase appears in any finding title, the item is "with issues".
# This is explicit and avoids fuzzy matching failures.
ITEM_FINDING_PATTERNS: dict[str, list[str]] = {
    "COOKIE-001": ["subdomain", "domain="],
    "COOKIE-002": ["httponly"],
    "COOKIE-003": ["secure flag", "secure cookie", "missing secure"],
    "COOKIE-004": ["samesite"],
    "HDR-001": ["strict-transport-security", "hsts"],
    "HDR-002": ["content-security-policy", "csp"],
    "HDR-003": ["x-frame-options", "frame-ancestors", "clickjacking"],
    "HDR-004": ["x-content-type-options"],
    "HDR-005": ["referrer-policy"],
    "HDR-006": ["permissions-policy"],
    "HDR-007": ["cors", "access-control-allow-origin"],
    "HDR-008": ["cache-control"],
    "HDR-009": ["host header"],
    "HDR-010": ["x-permitted-cross-domain"],
    "HDR-011": ["cross-origin-opener"],
    "HDR-012": ["cross-origin-resource"],
    "HDR-013": ["etag"],
    "DISC-001": ["credentials in source", "secret", "gitleaks"],
    "DISC-001b": ["api key", "aws access", "stripe", "github token", "google api", "slack token", "private key"],
    "DISC-002": ["error message", "verbose error"],
    "DISC-003": ["server technology", "x-powered-by", "server header"],
    "DISC-004": ["html comment"],
    "DISC-005": ["robots.txt"],
    "DISC-007": ["email address"],
    "DISC-008": ["internal ip"],
    "DISC-010": ["exif", "metadata"],
    "DISC-011": ["security.txt"],
    "GEN-005": ["unencrypted channel", "http available", "no https", "http only", "http without redirect", "http but https"],
    "GEN-011": ["crossdomain.xml"],
    "GEN-012": ["charset"],
    "GEN-015": ["clock", "synchroni"],
    "FORM-001": ["autocomplete"],
    "SESS-001": ["session fixation"],
    "SESS-002": ["persistent", "session cookie"],
    "SESS-006": ["entropy", "non-random", "sequential session", "predictab"],
    "AUTH-005": ["login form", "insecure http"],
    "PASS-003": ["credentials", "via get", "sensitive form data"],
    "PASS-004": ["not masked", "password field"],
    "CSRF-001": ["csrf token", "csrf attack"],
    "SUPPLY-003": ["subresource integrity", "sri"],
}


def _item_has_finding(item: ChecklistItem, finding_titles: list[str]) -> bool:
    """Check if any finding title indicates this checklist item has an issue.

    Uses explicit pattern matching from ITEM_FINDING_PATTERNS where available,
    falls back to keyword matching for items without explicit patterns.
    """
    all_titles_lower = " ||| ".join(t.lower() for t in finding_titles)

    # Check explicit patterns first
    patterns = ITEM_FINDING_PATTERNS.get(item.id, [])
    if patterns:
        return any(p.lower() in all_titles_lower for p in patterns)

    # Fallback: keyword matching for items without explicit patterns
    item_words = {w.lower() for w in item.title.split() if len(w) >= 4}
    item_words -= {"the", "not", "web", "application", "does", "are", "for",
                   "and", "with", "can", "via", "from", "has", "set", "all",
                   "missing", "enabled", "issues", "over", "used", "that",
                   "this", "been", "could", "would", "should", "items"}

    for title in finding_titles:
        title_lower = title.lower()
        matches = sum(1 for w in item_words if w in title_lower)
        if matches >= 2:
            return True

    return False


def get_coverage_summary(modules_run: list[str], finding_titles: list[str] | None = None) -> dict:
    """Calculate coverage statistics for the given set of modules.

    Args:
        modules_run: List of module names that were executed.
        finding_titles: List of all finding titles from the scan results.
            Used to determine which tested items passed vs found issues.

    Returns a dict with total items, covered counts by level, and uncovered items
    split into "skipped" (module exists but wasn't run) and "no_module" (no module built yet).
    Tested items are further split into "with_issues" and "passed".
    """
    active = get_active_items()
    all_finding_titles = finding_titles or []

    automated = []
    partial = []
    manual = []
    skipped = []      # Module exists but wasn't included in this scan
    no_module = []    # No module has been built for this item

    for item in active:
        if item.coverage == Coverage.MANUAL:
            manual.append(item)
        elif item.coverage == Coverage.NOT_COVERED:
            no_module.append(item)
        elif item.coverage in (Coverage.AUTOMATED, Coverage.PARTIAL):
            if any(m in modules_run for m in item.modules):
                if item.coverage == Coverage.AUTOMATED:
                    automated.append(item)
                else:
                    partial.append(item)
            else:
                skipped.append(item)
        else:
            no_module.append(item)

    # Split tested items into "with issues" vs "passed"
    # An item "passed" if its modules ran but no findings match this specific item
    all_with_issues = []
    all_passed = []
    for item in automated + partial:
        if _item_has_finding(item, all_finding_titles):
            all_with_issues.append(item)
        else:
            all_passed.append(item)

    # Determine which modules exist but weren't run
    all_known_modules = set()
    for item in active:
        all_known_modules.update(item.modules)
    modules_not_run = sorted(all_known_modules - set(modules_run))

    total = len(active)
    tested = len(automated) + len(partial)
    return {
        "modules_run": modules_run,
        "modules_not_run": modules_not_run,
        "total_items": total,
        "tested": tested,
        "automated": len(automated),
        "partial": len(partial),
        "manual": len(manual),
        "skipped": len(skipped),
        "no_module": len(no_module),
        "not_covered": len(skipped) + len(no_module),
        "coverage_percent": round(tested / total * 100, 1) if total else 0,
        "with_issues": len(all_with_issues),
        "passed": len(all_passed),
        "automated_items": automated,
        "partial_items": partial,
        "manual_items": manual,
        "skipped_items": skipped,
        "no_module_items": no_module,
        "with_issues_items": all_with_issues,
        "passed_items": all_passed,
        "not_covered_items": skipped + no_module,
    }
