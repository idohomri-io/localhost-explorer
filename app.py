import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.parse import urljoin

import psutil
import requests
import urllib3
from flask import Flask, jsonify, render_template

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.json.ensure_ascii = False
APP_PORT = int(os.environ.get("PORT", 5001))

# Host used in browser-side service links.
# Set the HOST env var to override (e.g. "myserver.local" or "192.168.1.10").
# Falls back to the machine's fully-qualified domain name.
SERVICE_HOST = os.environ.get("HOST") or socket.getfqdn()

print(f"Starting Localhost Explorer on {platform.system()}...")
print(f"Environment variables: PORT={APP_PORT}, HOST={SERVICE_HOST}")

KNOWN_PORTS = {
    80: ("HTTP Server", "fa-globe"),
    443: ("HTTPS Server", "fa-lock"),
    1080: ("SOCKS Proxy", "fa-shield-halved"),
    3000: ("React Dev Server", "fa-react"),
    3306: ("MySQL", "fa-database"),
    4200: ("Angular Dev Server", "fa-angular"),
    5000: ("Flask", "fa-pepper-hot"),
    5173: ("Vite", "fa-bolt"),
    5432: ("PostgreSQL", "fa-database"),
    5500: ("Live Server", "fa-broadcast-tower"),
    6379: ("Redis", "fa-server"),
    8000: ("Dev Server", "fa-code"),
    8080: ("HTTP Server", "fa-globe"),
    8443: ("HTTPS Alt", "fa-lock"),
    8888: ("Jupyter", "fa-book"),
    9090: ("Prometheus", "fa-chart-line"),
    9200: ("Elasticsearch", "fa-magnifying-glass"),
    27017: ("MongoDB", "fa-leaf"),
}

KNOWN_PROCESSES = {
    "node": ("Node.js", "fa-node-js"),
    "python": ("Python", "fa-python"),
    "python3": ("Python", "fa-python"),
    "nginx": ("Nginx", "fa-server"),
    "httpd": ("Apache", "fa-feather"),
    "redis-server": ("Redis", "fa-server"),
    "mongod": ("MongoDB", "fa-leaf"),
    "postgres": ("PostgreSQL", "fa-database"),
    "mysqld": ("MySQL", "fa-database"),
    "java": ("Java", "fa-java"),
    "ruby": ("Ruby", "fa-gem"),
    "php": ("PHP", "fa-php"),
    "deno": ("Deno", "fa-dinosaur"),
    "bun": ("Bun", "fa-bread-slice"),
}

LOCALHOST_ADDRS = {"127.0.0.1", "::1", "0.0.0.0", "::"}


# ---------------------------------------------------------------------------
# HTML meta-data extraction
# ---------------------------------------------------------------------------

class _MetaParser(HTMLParser):
    """Extract title, meta description, and favicon from HTML."""

    def __init__(self):
        super().__init__()
        self._in_title = False
        self.title = ""
        self.description = ""
        self.favicon = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name in ("description", "og:description") and not self.description:
                self.description = (a.get("content") or "").strip()
        elif tag == "link":
            rel = (a.get("rel") or "").lower()
            if "icon" in rel and not self.favicon:
                self.favicon = a.get("href", "")

    def handle_data(self, data):
        if self._in_title:
            self.title += data

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False


def _parse_response(resp, base_url):
    """Extract HTML metadata from a successful requests.Response."""
    if resp.status_code >= 400:
        return None
    if "html" not in resp.headers.get("content-type", ""):
        return None
    # requests defaults to ISO-8859-1 for text/html when no charset is
    # declared in the HTTP header, which mangles non-Latin scripts.
    resp.encoding = resp.apparent_encoding or "utf-8"
    parser = _MetaParser()
    parser.feed(resp.text[:32_000])
    favicon = parser.favicon
    if favicon:
        favicon = urljoin(base_url + "/", favicon)
    return {
        "title": parser.title.strip() or None,
        "description": parser.description or None,
        "favicon": favicon or None,
    }


def probe_http(port):
    """Try HTTPS (valid cert), HTTPS (self-signed), then HTTP on localhost:<port>.

    Returns a metadata dict with extra fields:
      protocol: "https" | "http"
      secure:   True  – HTTPS with a trusted certificate
                False – HTTPS with an untrusted / self-signed certificate
                None  – plain HTTP (no TLS)
    Returns None when no web service is found.
    """
    https_url = f"https://localhost:{port}"
    http_url  = f"http://localhost:{port}"

    # 1. HTTPS with certificate verification (trusted cert)
    try:
        resp = requests.get(https_url, timeout=1.5, allow_redirects=True, verify=True)
        meta = _parse_response(resp, https_url)
        if meta is not None:
            meta["protocol"] = "https"
            meta["secure"] = True
            return meta
    except requests.exceptions.SSLError:
        # Certificate problem — try again without verification
        try:
            resp = requests.get(https_url, timeout=1.5, allow_redirects=True, verify=False)
            meta = _parse_response(resp, https_url)
            if meta is not None:
                meta["protocol"] = "https"
                meta["secure"] = False
                return meta
        except Exception:
            pass
    except Exception:
        pass

    # 2. Plain HTTP
    try:
        resp = requests.get(http_url, timeout=1.5, allow_redirects=True)
        meta = _parse_response(resp, http_url)
        if meta is not None:
            meta["protocol"] = "http"
            meta["secure"] = None
            return meta
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Service discovery
# ---------------------------------------------------------------------------

def get_services():
    try:
        raw = _get_services_psutil()
    except psutil.AccessDenied:
        raw = _get_services_lsof()

    # Probe all ports for HTTP in parallel
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(probe_http, svc["port"]): svc for svc in raw}
        for fut in as_completed(futures):
            svc = futures[fut]
            meta = fut.result()
            if meta:
                svc["has_web"] = True
                svc["title"] = meta["title"]
                svc["description"] = meta["description"]
                svc["favicon"] = meta["favicon"]
                svc["protocol"] = meta["protocol"]
                svc["secure"] = meta["secure"]
            else:
                svc["has_web"] = False

    web = [s for s in raw if s["has_web"]]
    other = [s for s in raw if not s["has_web"]]
    web.sort(key=lambda s: s["port"])
    other.sort(key=lambda s: s["port"])
    return {"web": web, "other": other}


def _get_services_psutil():
    services = []
    seen_ports = set()

    for conn in psutil.net_connections(kind="tcp"):
        if conn.status != "LISTEN":
            continue
        ip, port = conn.laddr
        if ip not in LOCALHOST_ADDRS:
            continue
        if port == APP_PORT or port in seen_ports:
            continue
        seen_ports.add(port)

        proc_name = ""
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        friendly_name, icon = resolve_service(port, proc_name)

        services.append({
            "port": port,
            "process": proc_name,
            "name": friendly_name,
            "icon": icon,
        })

    services.sort(key=lambda s: s["port"])
    return services


def _get_services_lsof():
    """Fallback for macOS where psutil.net_connections() needs root."""
    services = []
    seen_ports = set()

    try:
        out = subprocess.check_output(
            ["lsof", "-iTCP", "-sTCP:LISTEN", "-nP", "-F", "pcn"],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return services

    pid = None
    proc_name = ""
    for line in out.splitlines():
        if line.startswith("p"):
            pid = line[1:]
            proc_name = ""
        elif line.startswith("c"):
            proc_name = line[1:]
        elif line.startswith("n"):
            # e.g. n127.0.0.1:8080 or n*:3000 or n[::1]:5000
            addr = line[1:]
            match = re.search(r":(\d+)$", addr)
            if not match:
                continue
            port = int(match.group(1))

            host = addr[:match.start()]
            # lsof wraps IPv6 in brackets, e.g. [::1] — strip them for comparison
            bare_host = host.strip("[]")
            if bare_host not in LOCALHOST_ADDRS and host not in ("*", "[::]"):
                continue
            if port == APP_PORT or port in seen_ports:
                continue
            seen_ports.add(port)

            friendly_name, icon = resolve_service(port, proc_name)
            services.append({
                "port": port,
                "process": proc_name,
                "name": friendly_name,
                "icon": icon,
            })

    services.sort(key=lambda s: s["port"])
    return services


def resolve_service(port, proc_name):
    if port in KNOWN_PORTS:
        return KNOWN_PORTS[port]

    proc_key = proc_name.lower().removesuffix(".exe")
    if proc_key in KNOWN_PROCESSES:
        return KNOWN_PROCESSES[proc_key]

    if proc_name:
        return (proc_name, "fa-plug")
    return (f"Port {port}", "fa-plug")


@app.route("/")
def index():
    return render_template("index.html", service_host=SERVICE_HOST)


@app.route("/api/services")
def api_services():
    return jsonify(get_services())


if __name__ == "__main__":
    app.run(port=APP_PORT, debug=True)
