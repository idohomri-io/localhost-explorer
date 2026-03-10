import csv
import io
import json
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

# When set, switches to TCP port-scan mode and probes this host instead of
# reading the local socket table. Required on macOS/Windows Docker Desktop
# where network_mode:host is unavailable. Typical value: "host.docker.internal".
SCAN_HOST = os.environ.get("SCAN_HOST")

print(f"Starting Localhost Explorer on {platform.system()}...")
print(f"Environment variables: PORT={APP_PORT}, HOST={SERVICE_HOST}, SCAN_HOST={SCAN_HOST}")

def _load_known_services():
    path = os.path.join(os.path.dirname(__file__), "known_ports.json")
    with open(path) as f:
        data = json.load(f)
    ports = {int(k): tuple(v) for k, v in data["ports"].items()}
    procs = {k: tuple(v) for k, v in data["processes"].items()}
    return ports, procs

KNOWN_PORTS, KNOWN_PROCESSES = _load_known_services()


_IANA_CSV = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

def _load_iana_ports() -> dict[int, str]:
    """Fetch IANA TCP port assignments and return {port: friendly_name}.

    Only TCP entries with a single port number and a non-empty description
    are included. Ports already in KNOWN_PORTS are skipped to avoid
    overwriting curated entries. Falls back to an empty dict on any error.
    """
    try:
        resp = requests.get(_IANA_CSV, timeout=5)
        resp.raise_for_status()
        result: dict[int, str] = {}
        for row in csv.DictReader(io.StringIO(resp.text)):
            port_str  = row.get("Port Number",        "").strip()
            proto     = row.get("Transport Protocol", "").strip().lower()
            svc_name  = row.get("Service Name",       "").strip()
            desc      = row.get("Description",        "").strip()
            if proto != "tcp" or not port_str or not port_str.isdigit():
                continue
            port = int(port_str)
            if port in result or port in KNOWN_PORTS:
                continue
            # Prefer the human-readable description when it's concise;
            # fall back to the service name in title case.
            name = desc if desc and len(desc) <= 45 else svc_name.replace("-", " ").title() if svc_name else None
            if name:
                result[port] = name
        print(f"Loaded {len(result)} port names from IANA registry.")
        return result
    except Exception as exc:
        print(f"IANA port list unavailable ({exc}); using known_ports.json only.")
        return {}

IANA_PORTS: dict[int, str] = _load_iana_ports()

LOCALHOST_ADDRS = {"127.0.0.1", "::1", "0.0.0.0", "::"}

# Cache of psutil.Process objects keyed by PID for CPU% tracking.
# cpu_percent(interval=None) needs two calls to return a non-zero value;
# reusing the same Process object across refreshes gives accurate readings.
_proc_cache: dict[int, psutil.Process] = {}


def _get_proc_stats(pid: int | None) -> tuple[float | None, int | None]:
    """Return (cpu_percent, memory_rss_bytes) for a PID, or (None, None)."""
    if not pid:
        return None, None
    try:
        if pid not in _proc_cache:
            _proc_cache[pid] = psutil.Process(pid)
        proc = _proc_cache[pid]
        return proc.cpu_percent(interval=None), proc.memory_info().rss
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        _proc_cache.pop(pid, None)
        return None, None


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


def probe_http(port, host="localhost"):
    """Try HTTPS (valid cert), HTTPS (self-signed), then HTTP on <host>:<port>.

    Returns a metadata dict with extra fields:
      protocol: "https" | "http"
      secure:   True  – HTTPS with a trusted certificate
                False – HTTPS with an untrusted / self-signed certificate
                None  – plain HTTP (no TLS)
    Returns None when no web service is found.
    """
    https_url = f"https://{host}:{port}"
    http_url  = f"http://{host}:{port}"

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
    if SCAN_HOST:
        raw = _get_services_scan(SCAN_HOST)
    else:
        try:
            raw = _get_services_psutil()
        except psutil.AccessDenied:
            raw = _get_services_lsof()

    # Probe all ports for HTTP in parallel
    probe_host = SCAN_HOST or "localhost"
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(probe_http, svc["port"], probe_host): svc for svc in raw}
        for fut in as_completed(futures):
            svc = futures[fut]
            meta = fut.result()
            if meta:
                svc["has_web"] = True
                svc["title"] = meta["title"]
                svc["description"] = meta["description"]
                # Favicon URL uses the internal probe host — rewrite it to the
                # browser-accessible SERVICE_HOST so the <img> loads correctly.
                favicon = meta["favicon"]
                if favicon and SCAN_HOST:
                    favicon = favicon.replace(f"://{SCAN_HOST}:", f"://{SERVICE_HOST}:", 1)
                svc["favicon"] = favicon
                svc["protocol"] = meta["protocol"]
                svc["secure"] = meta["secure"]
                svc["url"] = f"{meta['protocol']}://{SERVICE_HOST}:{svc['port']}"
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
        cpu_pct, mem_rss = _get_proc_stats(conn.pid)

        services.append({
            "port": port,
            "pid": conn.pid,
            "process": proc_name,
            "name": friendly_name,
            "icon": icon,
            "cpu_percent": cpu_pct,
            "memory_rss": mem_rss,
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
            try:
                pid = int(line[1:])
            except ValueError:
                pid = None
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
            cpu_pct, mem_rss = _get_proc_stats(pid)
            services.append({
                "port": port,
                "pid": pid,
                "process": proc_name,
                "name": friendly_name,
                "icon": icon,
                "cpu_percent": cpu_pct,
                "memory_rss": mem_rss,
            })

    services.sort(key=lambda s: s["port"])
    return services


def _get_services_scan(host):
    """TCP connect scan used on macOS/Windows Docker Desktop.

    psutil/lsof can't see the host's sockets from inside a Docker Desktop
    container, so we probe every port by attempting a TCP connection to
    `host` (typically "host.docker.internal").  Refused connections return
    in < 1 ms, so scanning all 65 535 ports completes in a few seconds.
    """
    import socket as _socket

    def _check(port):
        try:
            with _socket.create_connection((host, port), timeout=0.2):
                return port
        except Exception:
            return None

    services = []
    seen_ports = set()
    with ThreadPoolExecutor(max_workers=256) as pool:
        futures = [pool.submit(_check, p) for p in range(1, 65536)]
        for fut in as_completed(futures):
            port = fut.result()
            if port is None or port == APP_PORT or port in seen_ports:
                continue
            seen_ports.add(port)
            friendly_name, icon = resolve_service(port, "")
            services.append({
                "port": port,
                "pid": None,
                "process": "",
                "name": friendly_name,
                "icon": icon,
                "cpu_percent": None,
                "memory_rss": None,
            })

    services.sort(key=lambda s: s["port"])
    return services


def resolve_service(port, proc_name):
    if port in KNOWN_PORTS:
        return KNOWN_PORTS[port]

    proc_key = proc_name.lower().removesuffix(".exe")
    if proc_key in KNOWN_PROCESSES:
        return KNOWN_PROCESSES[proc_key]

    if port in IANA_PORTS:
        return (IANA_PORTS[port], "fa-plug")

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
    app.run(host="0.0.0.0", port=APP_PORT, debug=True)
