# Checklist-to-Tool Mapping

Maps checklist items to webscan modules.

The full checklist is implemented in code at `webscan/checklist.py` (154 items). This document is a readable summary.

## Coverage Legend

- **Automated** — Module fully tests this item
- **Partial** — Module detects some aspects; manual testing or ZAP may be needed for full coverage
- **Manual** — Requires human judgment or authenticated testing
- **Deprecated** — Item removed from active checklist (outdated technology)

---

## Cookie Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Cookies accessible by all subdomains | 3 | headers | Automated |
| HTTPOnly flag missing | 3 | headers | Automated |
| Secure flag missing | 3 | headers | Automated |
| SameSite attribute missing | 2 | headers | Automated |
| Cookie regulation / GDPR consent | 1 | — | Manual |

## Header Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| HSTS not enabled | 3 | headers | Automated |
| CSP not set | 2 | headers | Automated |
| X-Frame-Options / CSP frame-ancestors missing | 3 | headers | Automated |
| X-Content-Type-Options missing | 1 | headers | Automated |
| Referrer-Policy not set | 1 | headers | Automated |
| Permissions-Policy not set | 1 | headers | Automated |
| CORS misconfiguration (wildcard + reflected Origin) | 3 | headers | Automated |
| Cache-Control missing or permissive | 3 | headers | Automated |
| Host header poisoning | 3 | nuclei | Partial |
| X-Permitted-Cross-Domain-Policies missing | 1 | headers | Automated |
| COOP missing | 1 | headers | Automated |
| CORP missing | 1 | headers | Automated |
| ETag inode disclosure | 2 | headers, nikto | Automated |
| HPKP not enabled | — | — | Deprecated |
| X-XSS-Protection missing | — | — | Deprecated |

## Information Disclosure

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Credentials in source code / git history | 4 | gitleaks, trivy | Automated |
| API keys / secrets in live pages and JavaScript | 4 | disclosure | Automated |
| Verbose error messages | 3 | nikto, nuclei | Partial |
| Server technology disclosed via headers | 3 | headers, nikto | Automated |
| Information in HTML comments | 3 | disclosure | Automated |
| robots.txt discloses sensitive paths | 3 | headers | Automated |
| Internal filesystem path disclosure | 3 | nuclei, semgrep | Partial |
| Email addresses disclosed | 3 | disclosure | Automated |
| Internal IP address disclosed | 3 | disclosure, nuclei | Automated |
| Sensitive data in browser client storage | 3 | — | Manual |
| EXIF metadata disclosure | 1 | disclosure | Automated |
| security.txt missing | 0 | headers | Automated |

## Out of Date Software

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Vulnerable software / dependencies | 4 | trivy, nuclei, nikto, deps | Automated |
| Vulnerable framework version | 4 | trivy, nuclei | Partial |

## General Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| File inclusion (LFI/RFI) | 4 | nuclei, semgrep | Partial |
| WebDAV extensions enabled | 4 | nikto, nuclei | Automated |
| Dangerous HTTP methods | 4 | nikto, nuclei | Automated |
| GDPR / data protection compliance | 4 | — | Manual |
| No HTTPS / HTTP without redirect to HTTPS | 3 | headers | Automated |
| Backup files accessible | 3 | ffuf, nikto, nuclei | Automated |
| Directory indexing enabled | 3 | nikto, nuclei, ffuf | Automated |
| Directory traversal | 3 | nuclei, semgrep | Partial |
| Third-party CDN includes without SRI | 3 | disclosure | Automated |
| Default server content | 3 | nikto, nuclei | Automated |
| crossdomain.xml overly permissive | 3 | headers | Automated |
| Content-Type missing charset | 1 | headers | Automated |
| No custom error pages | 1 | nikto | Partial |
| GET/POST methods interchangeable | 1 | api_routes | Partial |
| Server clock not synchronised | 1 | headers | Automated |
| Webserver runs as root | 3 | — | Manual |
| Relative Path Overwrite (RPO) | 2 | — | Manual |
| Incorrectly states Content-Type | 2 | — | Manual |
| Contains unnecessary content | 1 | — | Manual |
| NTLM authentication supported | 3 | nuclei | Partial |

## Forms

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Autocomplete on sensitive fields | 3 | forms | Automated |
| CAPTCHA bypass | 3 | — | Manual |
| No anti-automation / rate limiting | 1 | — | Manual |

## Injections

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| SQL injection | 4 | sqlmap, nuclei, semgrep | Automated |
| Blind SQL injection | 4 | sqlmap | Automated |
| Command execution | 4 | nuclei, semgrep | Partial |
| XXE | 4 | nuclei, semgrep | Partial |
| Server-side includes injection | 4 | nuclei | Partial |
| SSRF | 4 | nuclei, semgrep | Partial |
| Insecure deserialization | 4 | semgrep | Partial |
| HTTP request smuggling | 4 | nuclei | Partial |
| Reflected XSS | 3 | nuclei | Partial |
| Stored XSS | 3 | nuclei | Partial |
| DOM-based XSS | 3 | semgrep | Partial |
| Server-Side Template Injection (SSTI) | 4 | nuclei, semgrep | Partial |
| Prototype pollution (JS) | 3 | semgrep | Partial |
| XML injection | 3 | nuclei, semgrep | Partial |
| Email injection | 3 | semgrep | Partial |
| Input validation flaws | 3 | semgrep | Partial |
| Excel formula injection | 3 | semgrep | Partial |
| XPath injection | 3 | nuclei, semgrep | Partial |
| SQL wildcards | 3 | — | Manual |
| Direct control over SQL queries | 3 | semgrep | Partial |
| Open redirect | 2 | nuclei | Partial |
| HTML injection | 2 | nuclei | Partial |
| Null character injection | 2 | — | Manual |
| Static text injection | 2 | — | Manual |
| PDF generation injection (SSRF/XSS) | 3 | semgrep | Partial |

## File Upload Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Arbitrary file uploads | 4 | nuclei, semgrep | Partial |
| File upload without malware protection | 3 | — | Manual |

## Session Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Session fixation | 3 | session | Partial |
| Session not terminated on browser close | 3 | session | Automated |
| Sessions not expired on logout | 3 | — | Manual |
| No session timeout | 3 | — | Manual |
| No account lockout policy | 3 | — | Manual |
| DoS via account lockout | 3 | — | Manual |
| Non-random session IDs | 3 | session | Automated |
| Session ID passed in URL | 3 | semgrep, nuclei | Partial |
| Application switches between HTTP and HTTPS | 3 | testssl, headers | Partial |
| Users unable to logout | 2 | — | Manual |

## Authentication Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Authentication bypass | 4 | api_routes, nuclei | Partial |
| Broken Object Level Authorization (BOLA/IDOR) | 4 | — | Manual |
| Weak access control / unauth access | 3 | api_routes | Partial |
| Admin login page exposed | 3 | ffuf, nikto, nuclei | Automated |
| User enumeration | 3 | — | Manual |
| Login form over insecure channel | 2 | forms | Automated |
| Sensitive information in cookies | 2 | session | Partial |
| JWT implementation flaws | 4 | — | Not covered (Phase 4) |
| Mass assignment / parameter pollution | 3 | semgrep | Partial |
| Broken function-level authorization | 4 | api_routes | Partial |
| Concurrent logins | 1 | — | Manual |
| Username not case-sensitive | 1 | — | Manual |
| Does not display last login | 1 | — | Manual |
| Does not display secure use policy | 1 | — | Manual |

## Password Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Weak password policy | 3 | — | Manual |
| Default / weak credentials | 3 | nuclei | Partial |
| Login credentials sent via GET | 3 | forms, semgrep | Partial |
| Password fields not masked | 3 | forms | Automated |
| Insecure forgotten password | 3 | — | Manual |
| Passwords stored in plaintext (source) | 3 | semgrep | Partial |
| 200 response after password submission | 3 | forms | Partial |
| No forced password change on first login | 3 | — | Manual |
| Passwords not case-sensitive | 2 | — | Manual |
| Fragment-of-password authentication | 2 | — | Manual |
| Remember Me feature | 2 | — | Manual |
| Unable to change password | 2 | — | Manual |
| Keystroke logging vulnerability | 2 | — | Manual |
| Security questions can be blank | 2 | — | Manual |
| Weak memorable data enforcement | 2 | — | Manual |
| Inadequate password history | 1 | — | Manual |

## CSRF Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| CSRF attacks | 3 | forms, nuclei, semgrep | Partial |
| CSRF token passed in URL | 3 | semgrep | Partial |
| CSRF token not dynamic / replayable | 2 | — | Manual |

## Privilege Escalation

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Horizontal/vertical privilege escalation | 3 | api_routes | Partial |

## SSL/TLS Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Outdated TLS protocols (SSLv2/3, TLS 1.0/1.1) | 3 | testssl | Automated |
| Weak cipher suites | 3 | testssl | Automated |
| Forward secrecy not supported/mandated | 2 | testssl | Automated |
| Certificate issues (expired, untrusted, weak hash, key size, CN mismatch) | 3 | testssl | Automated |
| Known TLS vulnerabilities (POODLE, BEAST, etc.) | 3 | testssl | Automated |

## Supply Chain

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Vulnerable dependencies (known CVEs) | 4 | trivy, deps | Automated |
| Dependency confusion / typosquatting | 4 | deps | Automated |
| Subresource Integrity (SRI) missing | 2 | disclosure | Automated |
| Dependencies with lifecycle scripts | 3 | deps | Automated |
| Low-popularity packages | 3 | deps | Automated |
| Suspicious code patterns in dependencies | 4 | deps | Automated |

## API Security

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| GraphQL introspection in production | 3 | — | Not covered (Phase 4) |
| API rate limiting missing | 3 | — | Manual |
| Subdomain takeover | 3 | nuclei | Partial |
| Excessive data exposure in API responses | 3 | semgrep | Partial |
| Broken function-level authorization | 4 | api_routes | Partial |

## Protocol Issues

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| HTTP/2 request smuggling | 4 | nuclei | Partial |
| WebSocket hijacking (CSWSH) | 3 | — | Not covered (Phase 4) |
| DNS rebinding | 3 | — | Manual |

## OAuth / Identity

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| OAuth open redirect in callback | 3 | semgrep | Partial |
| OAuth state parameter missing | 3 | semgrep | Partial |
| OAuth token leakage | 3 | semgrep | Partial |

## Authorization

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| IDOR on file/resource access | 4 | — | Manual |
| CORS with reflected Origin | 3 | headers | Partial |

## Age and Location Restrictions

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Age/location verification bypass | 3 | — | Manual |
| Age verification bypass (client-side) | 3 | — | Manual |

## Business Logic

| Item | Sev | Module(s) | Coverage |
|------|-----|-----------|----------|
| Race conditions / TOCTOU | 3 | — | Manual |

---

## Remaining gaps

### Not covered — no module built yet (Phase 4)
- JWT implementation flaws — planned `jwt.py` module
- GraphQL introspection — planned `graphql.py` module
- WebSocket hijacking — planned module or ZAP

### Best covered by ZAP (Phase 4)
- XSS (all types) — comprehensive dynamic testing
- CSRF — full token validation testing
- File inclusion — dynamic payload testing
- Session fixation — full authentication flow
- File upload testing — payload-based
- User enumeration — response timing analysis
- Auth bypass — multi-context testing

### Inherently manual
- GDPR/cookie compliance, CAPTCHA bypass, password policy, password reset flow, account lockout, concurrent logins, age verification, unnecessary content, keystroke logging, security questions
