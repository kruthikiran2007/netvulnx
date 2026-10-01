"""HTTP(S) service analysis — one careful request per service.

Read-only observations from a single GET / (plus redirect hops):
  - redirect chain (followed MANUALLY, max 5 hops, so each hop is evidence)
  - Server / X-Powered-By headers (version disclosure clues)
  - security header presence: HSTS, CSP, X-Frame-Options, ...
  - http -> https upgrade behavior
  - directory listing / default-page indicators (from a small body sniff)

We use http.client directly (not urllib/requests) for full control:
no automatic redirect following, no cookie jar, tiny body reads.
"""
import http.client
import re
import socket
import ssl
import urllib.parse

MAX_REDIRECTS = 5
MAX_BODY = 32 * 1024  # we only sniff the head of the page (title etc.)

# Header -> what its absence means, in plain language for the UI later.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# <title> snippets that reveal an untouched default installation.
_DEFAULT_PAGES = [
    ("welcome to nginx", "nginx default page"),
    ("apache2 ubuntu default page", "Apache default page"),
    ("apache http server test page", "Apache test page"),
    ("iis windows server", "IIS default page"),
    ("xampp", "XAMPP default page"),
]


def _nonverifying_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspect, don't trust (same as tlscheck)
    return ctx


def _make_conn(parsed: urllib.parse.ParseResult, timeout: float):
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=timeout,
                                           context=_nonverifying_context())
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _page_title(body: bytes) -> str:
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    if not m:
        return ""
    return re.sub(rb"\s+", b" ", m.group(1)).decode("utf-8",
                                                    errors="replace").strip()


def analyze_http(host: str, port: int, use_tls: bool = False,
                 timeout: float = 5.0) -> dict:
    """Analyze one HTTP(S) service. Never raises; errors are in the dict."""
    scheme = "https" if use_tls else "http"
    default_port = 443 if use_tls else 80
    start = f"{scheme}://{host}:{port}/"

    chain = []
    current = start
    final = None
    http_error = None
    for _ in range(MAX_REDIRECTS + 1):
        try:
            parsed = urllib.parse.urlparse(current)
            conn = _make_conn(parsed, timeout)
            try:
                host_header = parsed.hostname
                if parsed.port and parsed.port != default_port:
                    host_header += f":{parsed.port}"
                conn.request("GET", parsed.path or "/",
                             headers={"Host": host_header,
                                      "User-Agent": "NetVulnX/1.0",
                                      "Connection": "close"})
                resp = conn.getresponse()
                try:
                    body = resp.read(MAX_BODY)
                except (http.client.IncompleteRead, OSError) as exc:
                    body = getattr(exc, "partial", b"")
                headers = {k.lower(): v for k, v in resp.getheaders()}
            finally:
                conn.close()
        except Exception as exc:
            http_error = f"HTTP request failed: {type(exc).__name__}: {exc}"
            break

        location = headers.get("location")
        chain.append({"url": current, "status": resp.status,
                      "location": location})
        if resp.status in (301, 302, 303, 307, 308) and location:
            if len(chain) > MAX_REDIRECTS:
                http_error = f"too many redirects (>{MAX_REDIRECTS})"
                break
            current = urllib.parse.urljoin(current, location)
            continue
        final = {"status": resp.status, "headers": headers, "body": body,
                 "url": current}
        break

    redirects_to_https = any(
        urllib.parse.urlparse(step["url"]).scheme == "http"
        and step["location"]
        and urllib.parse.urlparse(
            urllib.parse.urljoin(step["url"], step["location"])).scheme == "https"
        for step in chain
    )
    if http_error is not None or final is None:
        return {"error": http_error or "no HTTP response",
                "redirect_chain": chain,
                "redirects_to_https": redirects_to_https}

    headers = final["headers"]
    title = _page_title(final["body"])
    title_lower = title.lower()

    security = {name: headers.get(name) for name in SECURITY_HEADERS}
    default_page = next((label for needle, label in _DEFAULT_PAGES
                         if needle in title_lower), None)

    return {
        "error": None,
        "scheme": scheme,
        "final_url": final["url"],
        "status_code": final["status"],
        "redirect_chain": chain,
        "server_header": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "security_headers": {k: v for k, v in security.items() if v is not None},
        "missing_security_headers": [SECURITY_HEADERS[k]
                                     for k, v in security.items() if v is None],
        "redirects_to_https": redirects_to_https,
        "page_title": title[:120] or None,
        "directory_listing": title_lower.startswith("index of"),
        "default_page": default_page,
    }
