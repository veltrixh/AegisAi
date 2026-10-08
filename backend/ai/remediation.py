from typing import Dict, Any, List
from backend.models.finding import FindingModel
from backend.ai.provider import get_ai_provider, OfflineDeterministicProvider
from backend.utils.logger import logger

class RemediationEngine:
    """
    Generates actionable, production-ready remediation blueprints and
    multi-language code patterns (Python, JavaScript/Node.js, Java, PHP).
    """

    @classmethod
    async def generate_remediation(cls, finding: FindingModel) -> Dict[str, Any]:
        vuln_type = finding.type.lower()
        param = finding.parameter or "input"

        if "sql" in vuln_type:
            return {
                "problem": f"User-controlled parameter '{param}' is incorporated directly into database queries without parameterization.",
                "recommendation": "Use parameterized queries / prepared statements via ORMs or native DB drivers. Never concatenate unescaped input into SQL strings.",
                "verification": f"Re-run the scanner with profile 'standard' or 'deep' and verify that the SQL syntax error signature and behavioral difference on '{param}' disappear.",
                "code_examples": {
                    "python": (
                        "# Python (psycopg2 / sqlite3)\n"
                        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))\n"
                        "# SQLAlchemy ORM\n"
                        "session.query(User).filter(User.id == user_input).first()"
                    ),
                    "javascript": (
                        "// Node.js (pg / mysql2)\n"
                        "const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);\n"
                        "// Prisma ORM\n"
                        "const user = await prisma.user.findUnique({ where: { id: userId } });"
                    ),
                    "java": (
                        "// Java PreparedStatement\n"
                        "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n"
                        "stmt.setString(1, userId);\n"
                        "ResultSet rs = stmt.executeQuery();"
                    ),
                    "php": (
                        "// PHP PDO Prepared Statement\n"
                        "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
                        "$stmt->execute(['id' => $userId]);\n"
                        "$user = $stmt->fetch();"
                    )
                }
            }

        elif "xss" in vuln_type:
            return {
                "problem": f"User-controllable input from parameter '{param}' is reflected in the HTML response without contextual escaping.",
                "recommendation": "Encode all dynamic values before rendering in HTML context using context-aware encoders. Implement a strict Content-Security-Policy (CSP) header.",
                "verification": f"Submit benign probe strings like '<script>alert(1)</script>' to parameter '{param}' and verify the output is encoded as '&lt;script&gt;'.",
                "code_examples": {
                    "python": (
                        "# Python (Jinja2 automatically escapes by default)\n"
                        "import html\n"
                        "safe_output = html.escape(user_input)\n"
                        "return render_template('index.html', q=safe_output)"
                    ),
                    "javascript": (
                        "// Node.js (DOMPurify / sanitize-html)\n"
                        "const sanitizeHtml = require('sanitize-html');\n"
                        "const clean = sanitizeHtml(userQuery, { allowedTags: [] });\n"
                        "// React safely escapes JSX values by default: <div>{userQuery}</div>"
                    ),
                    "java": (
                        "// Java OWASP Java HTML Sanitizer\n"
                        "import org.owasp.encoder.Encode;\n"
                        "String safe = Encode.forHtml(userInput);"
                    ),
                    "php": (
                        "// PHP htmlspecialchars\n"
                        "$safe_output = htmlspecialchars($user_input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');\n"
                        "echo $safe_output;"
                    )
                }
            }

        elif "csrf" in vuln_type:
            return {
                "problem": f"State-changing endpoint '{finding.target}' accepts requests without validating unpredictable anti-CSRF tokens.",
                "recommendation": "Implement cryptographic anti-CSRF tokens for all state-changing methods (POST, PUT, DELETE). Enforce SameSite=Lax or SameSite=Strict on session cookies.",
                "verification": "Attempt a state-changing POST request without the anti-CSRF token header or payload, and verify that the server returns HTTP 403 Forbidden.",
                "code_examples": {
                    "python": (
                        "# FastAPI / Starlette CSRF Middleware\n"
                        "# Or Django: Ensure 'django.middleware.csrf.CsrfViewMiddleware' is active\n"
                        "# Flask-WTF:\n"
                        "from flask_wtf.csrf import CSRFProtect\n"
                        "csrf = CSRFProtect(app)"
                    ),
                    "javascript": (
                        "// Express.js csurf middleware or double-submit cookie pattern\n"
                        "const csrf = require('csurf');\n"
                        "app.use(csrf({ cookie: { httpOnly: true, sameSite: 'lax', secure: true } }));"
                    ),
                    "java": (
                        "// Spring Security automatically enables CSRF protection by default\n"
                        "http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());"
                    ),
                    "php": (
                        "// PHP Session Token Verification\n"
                        "if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {\n"
                        "    http_response_code(403);\n"
                        "    die('CSRF token validation failed');\n"
                        "}"
                    )
                }
            }

        elif "ssrf" in vuln_type:
            return {
                "problem": f"Server fetches remote resources based on user-supplied URL parameter '{param}' without destination validation.",
                "recommendation": "Use a strict allowlist of permitted domain names and protocols. Disable HTTP redirects in the fetching client. Block loopback, link-local, and private IP ranges at the network and DNS resolution layers.",
                "verification": "Test with loopback (127.0.0.1) or AWS metadata IP (169.254.169.254) and confirm the request is immediately rejected with HTTP 400/403.",
                "code_examples": {
                    "python": (
                        "import ipaddress, socket, urllib.parse\n"
                        "def safe_fetch(url):\n"
                        "    parsed = urllib.parse.urlparse(url)\n"
                        "    ip = socket.gethostbyname(parsed.hostname)\n"
                        "    if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:\n"
                        "        raise ValueError('Access to private network forbidden')\n"
                        "    return httpx.get(url, follow_redirects=False)"
                    ),
                    "javascript": (
                        "// Node.js SSRF prevention with ssrf-req-filter or ip-range-check\n"
                        "const isPrivate = require('is-private-ip');\n"
                        "const dns = require('dns').promises;\n"
                        "const { address } = await dns.lookup(url.hostname);\n"
                        "if (isPrivate(address)) throw new Error('Private IP access rejected');"
                    ),
                    "java": (
                        "// Java validation before HTTP connection\n"
                        "InetAddress addr = InetAddress.getByName(uri.getHost());\n"
                        "if (addr.isSiteLocalAddress() || addr.isLoopbackAddress()) {\n"
                        "    throw new SecurityException(\"SSRF protection blocked request\");\n"
                        "}"
                    ),
                    "php": (
                        "// PHP cURL Safe configuration\n"
                        "$ip = gethostbyname($host);\n"
                        "if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {\n"
                        "    die('Access to internal hosts blocked');\n"
                        "}"
                    )
                }
            }

        elif "header" in vuln_type or "cookie" in vuln_type:
            return {
                "problem": "Missing defense-in-depth HTTP security headers and/or cookie protection flags.",
                "recommendation": "Configure standard security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options: DENY, X-Content-Type-Options: nosniff. Set HttpOnly, Secure, and SameSite=Lax on all session cookies.",
                "verification": "Issue an HTTP HEAD request against the target and inspect the response headers to verify presence of CSP, HSTS, and X-Content-Type-Options.",
                "code_examples": {
                    "python": (
                        "# FastAPI Security Headers Middleware\n"
                        "@app.middleware('http')\n"
                        "async def add_security_headers(request, call_next):\n"
                        "    resp = await call_next(request)\n"
                        "    resp.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
                        "    resp.headers['X-Content-Type-Options'] = 'nosniff'\n"
                        "    resp.headers['X-Frame-Options'] = 'DENY'\n"
                        "    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n"
                        "    return resp"
                    ),
                    "javascript": (
                        "// Express.js with Helmet\n"
                        "const helmet = require('helmet');\n"
                        "app.use(helmet());"
                    ),
                    "java": (
                        "// Spring Security headers configuration\n"
                        "http.headers()\n"
                        "    .contentSecurityPolicy(\"default-src 'self'\")\n"
                        "    .and().frameOptions().deny();"
                    ),
                    "php": (
                        "// PHP Core Header directives or Nginx/Apache config\n"
                        "header(\"Content-Security-Policy: default-src 'self'\");\n"
                        "header('X-Content-Type-Options: nosniff');\n"
                        "header('X-Frame-Options: DENY');"
                    )
                }
            }

        else:
            return {
                "problem": f"Security configuration discrepancy identified on target '{finding.target}'.",
                "recommendation": "Review authorization policies, apply input validation and output encoding, and enforce least privilege access.",
                "verification": "Re-run the vulnerability assessment to verify that the security control is enforced.",
                "code_examples": {
                    "python": "# Enforce strict input validation using Pydantic or schema validators\nclass SafeInput(BaseModel):\n    param: str = Field(..., max_length=100)",
                    "javascript": "// Enforce input validation using Zod or Joi schemas\nconst schema = z.object({ param: z.string().max(100) });",
                    "java": "// Enforce validation with Jakarta Bean Validation\n@NotNull @Size(max = 100) private String param;",
                    "php": "// Validate inputs with filter_var\n$safe = filter_input(INPUT_GET, 'param', FILTER_SANITIZE_SPECIAL_CHARS);"
                }
            }
