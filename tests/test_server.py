"""Deliberately vulnerable test server for local smoke testing.

DO NOT deploy this anywhere. It exists solely for testing webscan tools
against localhost in a controlled environment.

Each endpoint is annotated with the webscan module(s) it exercises.

Usage:
    python tests/test_server.py
    # Starts on http://127.0.0.1:8999
"""

import json
import random
import sqlite3
import string
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


def init_db() -> sqlite3.Connection:
    """Create an in-memory SQLite database with test data."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'Alice', 'alice@example.com')")
    conn.execute("INSERT INTO users VALUES (2, 'Bob', 'bob@example.com')")
    conn.commit()
    return conn


DB = init_db()

# Simple incrementing session counter — deliberately weak
_session_counter = 1000


def _weak_session_id() -> str:
    """Generate a deliberately weak, predictable session ID."""
    global _session_counter
    _session_counter += 1
    # Prefix + sequential number = low entropy, predictable
    return f"sess_{_session_counter}"


class TestHandler(BaseHTTPRequestHandler):
    """HTTP handler with deliberately vulnerable and discoverable endpoints.

    Vulnerability coverage by module:
        headers:     /, /profile (weak headers, cookies, CORS, banners, cache)
        disclosure:  / (HTML comments, emails, internal IPs, external scripts without SRI)
        forms:       /login, /register, /payment (CSRF, autocomplete, masking, GET creds)
        session:     / (weak session IDs — sequential, low entropy, persistent)
        nikto:       all (server banner, default content, methods)
        ffuf:        all (discoverable paths)
        sqlmap:      /api/search (SQL injection)
        nuclei:      all (various templates)
    """

    def log_message(self, format, *args):
        """Suppress request logging to keep output clean."""
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        routes = {
            "/": self.handle_index,
            "/admin": self.handle_admin,
            "/api/users": self.handle_users,
            "/api/health": self.handle_health,
            "/api/search": self.handle_search,
            "/robots.txt": self.handle_robots,
            "/server-status": self.handle_server_status,
            "/.env": self.handle_env,
            "/backup": self.handle_backup,
            "/login": self.handle_login,
            "/register": self.handle_register,
            "/payment": self.handle_payment,
            "/profile": self.handle_profile,
            "/crossdomain.xml": self.handle_crossdomain,
        }

        handler = routes.get(path)
        if handler:
            handler(params)
        else:
            self.send_error(404, "Not Found")

    # ------------------------------------------------------------------
    # Index — exercises: headers, disclosure, session
    # ------------------------------------------------------------------
    def handle_index(self, params):
        """Home page with deliberately weak headers and information disclosure."""
        self.send_response(200)
        # headers module: missing security headers, tech disclosure
        self.send_header("Content-Type", "text/html")  # No charset
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "Express")
        self.send_header("Access-Control-Allow-Origin", "*")
        # session module: weak, sequential, persistent session cookie
        sid = _weak_session_id()
        self.send_header("Set-Cookie", f"session={sid}; Path=/; Max-Age=86400")
        # headers module: permissive caching
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()

        # disclosure module: HTML comments, emails, internal IPs, external scripts without SRI
        self.wfile.write(b"""<html>
<head>
    <title>Test App</title>
    <!-- TODO: remove debug endpoints before production deploy -->
    <!-- FIXME: password reset token is not expiring properly -->
    <!-- Build version: 3.2.1-beta, deployed by jenkins@build-server -->
    <script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.example.com/analytics.js"></script>
    <link rel="stylesheet" href="https://cdn.example.com/bootstrap.min.css">
</head>
<body>
    <h1>Test Application</h1>
    <p>Welcome to our application.</p>
    <!-- Internal API endpoint: http://192.168.1.50:8080/internal-api -->
    <nav>
        <a href="/login">Login</a>
        <a href="/register">Register</a>
        <a href="/profile">Profile</a>
        <a href="/payment">Payment</a>
        <a href="/admin">Admin</a>
        <a href="/api/health">API Health</a>
        <a href="/api/users">API Users</a>
        <a href="/api/search?q=test">Search</a>
    </nav>
    <p>For support, contact support@testcompany.com or admin@testcompany.com</p>
    <p>Backend server: 10.0.0.25</p>
    <footer>
        <p>Questions? Email helpdesk@testcompany.com</p>
    </footer>
</body>
</html>""")

    # ------------------------------------------------------------------
    # Login — exercises: forms (CSRF, POST)
    # ------------------------------------------------------------------
    def handle_login(self, params):
        """Login page — POST form without CSRF token."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        # forms module: POST form without CSRF token
        self.wfile.write(b"""<html><body>
<h1>Login</h1>
<form method="post" action="/login">
    <label>Username: <input type="text" name="username"></label><br>
    <label>Password: <input type="password" name="password"></label><br>
    <button type="submit">Login</button>
</form>
<p>Don't have an account? <a href="/register">Register here</a></p>
<p><a href="/">Back to home</a></p>
</body></html>""")

    # ------------------------------------------------------------------
    # Register — exercises: forms (GET credentials, unmasked password)
    # ------------------------------------------------------------------
    def handle_register(self, params):
        """Registration page — credentials via GET, unmasked password field."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        # forms module: GET method with password, password field not type=password
        self.wfile.write(b"""<html><body>
<h1>Register</h1>
<form method="get" action="/register">
    <label>Email: <input type="text" name="email"></label><br>
    <label>Password: <input type="text" name="password"></label><br>
    <label>Confirm: <input type="text" name="confirm_password"></label><br>
    <button type="submit">Register</button>
</form>
<p>Already have an account? <a href="/login">Login here</a></p>
<p><a href="/">Back to home</a></p>
</body></html>""")

    # ------------------------------------------------------------------
    # Payment — exercises: forms (autocomplete on sensitive fields)
    # ------------------------------------------------------------------
    def handle_payment(self, params):
        """Payment page — sensitive fields without autocomplete=off."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        # forms module: autocomplete on credit card, CVV, and SSN fields
        self.wfile.write(b"""<html><body>
<h1>Payment</h1>
<form method="post" action="/payment">
    <input type="hidden" name="csrf_token" value="abc123">
    <label>Name: <input type="text" name="name"></label><br>
    <label>Card Number: <input type="text" name="credit_card"></label><br>
    <label>CVV: <input type="text" name="cvv"></label><br>
    <label>SSN: <input type="text" name="ssn"></label><br>
    <button type="submit">Pay</button>
</form>
</body></html>""")

    # ------------------------------------------------------------------
    # Profile — exercises: headers (additional weak headers)
    # ------------------------------------------------------------------
    def handle_profile(self, params):
        """Profile page — ETag with inode, no cache control."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # headers module: inode-style ETag
        self.send_header("ETag", '"2a-5f-63b1c8a0"')
        # headers module: backend IP in header
        self.send_header("X-Backend-Server", "10.0.0.5:8080")
        self.send_header("X-AspNet-Version", "4.0.30319")
        self.end_headers()
        self.wfile.write(b"""<html><body>
<h1>User Profile</h1>
<p>Username: alice</p>
<!-- DEBUG: user_id=42, role=admin, last_ip=192.168.1.105 -->
</body></html>""")

    # ------------------------------------------------------------------
    # Admin — exercises: ffuf, nikto, api_routes (unauth access)
    # ------------------------------------------------------------------
    def handle_admin(self, params):
        """Admin panel — accessible without auth."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"""<html><body>
<h1>Admin Panel</h1>
<p>Welcome, admin!</p>
<!-- Note: default admin credentials are admin/admin123 -->
<a href="/server-status">Server Status</a>
<a href="/backup">Backups</a>
<a href="/.env">Environment</a>
<a href="/">Back to home</a>
</body></html>""")

    # ------------------------------------------------------------------
    # API endpoints — exercises: sqlmap, api_routes
    # ------------------------------------------------------------------
    def handle_users(self, params):
        """API endpoint returning user data."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        cursor = DB.execute("SELECT * FROM users")
        users = [{"id": r[0], "name": r[1], "email": r[2]} for r in cursor.fetchall()]
        self.wfile.write(json.dumps(users).encode())

    def handle_health(self, params):
        """Health check endpoint."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode())

    def handle_search(self, params):
        """Deliberately SQL-injectable search endpoint."""
        query = params.get("q", [""])[0]
        try:
            # DELIBERATELY VULNERABLE — string interpolation in SQL
            sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
            cursor = DB.execute(sql)
            results = [{"id": r[0], "name": r[1], "email": r[2]} for r in cursor.fetchall()]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(results).encode())
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            # Deliberately leaks error details
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    # ------------------------------------------------------------------
    # Well-known files — exercises: headers, ffuf, nikto
    # ------------------------------------------------------------------
    def handle_robots(self, params):
        """robots.txt revealing hidden paths."""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"User-agent: *\n"
                         b"Disallow: /admin\n"
                         b"Disallow: /backup\n"
                         b"Disallow: /server-status\n"
                         b"Disallow: /internal\n"
                         b"Disallow: /debug\n")

    def handle_crossdomain(self, params):
        """Overly permissive crossdomain.xml."""
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(b"""<?xml version="1.0"?>
<cross-domain-policy>
    <allow-access-from domain="*"/>
</cross-domain-policy>""")

    def handle_server_status(self, params):
        """Server status page (information disclosure)."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"""<html><body>
<h1>Server Status</h1>
<p>Uptime: 42 days</p>
<p>Connections: 1234</p>
<p>Internal gateway: 172.16.0.1</p>
</body></html>""")

    def handle_env(self, params):
        """Exposed .env file."""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"DB_HOST=localhost\n"
                         b"DB_PASSWORD=supersecret123\n"
                         b"API_KEY=sk-test-fake-key-12345\n")

    def handle_backup(self, params):
        """Backup directory listing."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"""<html><body>
<h1>Backup Files</h1>
<a href='backup.sql'>backup.sql</a><br>
<a href='users_export.csv'>users_export.csv</a>
</body></html>""")

    # ------------------------------------------------------------------
    # POST handlers
    # ------------------------------------------------------------------
    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><p>Invalid credentials</p></body></html>")
        elif parsed.path == "/payment":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><p>Payment processed</p></body></html>")
        else:
            self.send_error(404)


HOST = "127.0.0.1"
PORT = 8999


def start_server() -> HTTPServer:
    """Start the test server in a background thread. Returns the server instance."""
    server = HTTPServer((HOST, PORT), TestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


if __name__ == "__main__":
    print(f"Test server starting on http://{HOST}:{PORT}")
    print("Endpoints:")
    print("  /                 - Home (weak headers, comments, emails, IPs, no SRI)")
    print("  /login            - Login form (no CSRF token)")
    print("  /register         - Register form (GET creds, unmasked password)")
    print("  /payment          - Payment form (autocomplete on card/CVV/SSN)")
    print("  /profile          - Profile (ETag inode, backend IP, debug comments)")
    print("  /admin            - Admin panel (no auth, default creds in comment)")
    print("  /api/users        - User API (JSON)")
    print("  /api/health       - Health check")
    print("  /api/search?q=    - Search (SQL injectable)")
    print("  /robots.txt       - Sensitive paths disclosed")
    print("  /crossdomain.xml  - Wildcard cross-domain policy")
    print("  /server-status    - Internal IP disclosure")
    print("  /.env             - Exposed credentials")
    print("  /backup           - Directory listing")
    print("Press Ctrl+C to stop")
    server = HTTPServer((HOST, PORT), TestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        print("\nServer stopped.")
