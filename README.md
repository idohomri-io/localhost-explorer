# Localhost Explorer

A lightweight dashboard that discovers and displays all services running on your local machine.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Flask](https://img.shields.io/badge/flask-3.x-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Automatic service discovery** — scans all listening TCP ports via `psutil` (falls back to `lsof` on macOS)
- **Web vs. Other classification** — ports that serve HTML with a 2xx response appear as rich cards; everything else (non-HTTP, error responses, databases, etc.) appears in a compact list
- **Rich web cards** — fetches page title, meta description, and favicon for each web service
- **Live refresh** — rescans every 30 seconds and immediately on tab focus; click the status chip to trigger a manual scan
- **New service notifications** — opt-in browser notifications when a new port appears while the tab is in the background (preference stored in `localStorage`)
- **Fixed header** — app title, status indicator, and notification toggle always visible at the top

## Requirements

- Python 3.10+
- macOS, Linux, or Windows

## Installation

```bash
git clone https://github.com/your-username/localhost-explorer.git
cd localhost-explorer
pip install -r requirements.txt
```

## Usage

```bash
python app.py
```

Then open [http://localhost:5001](http://localhost:5001) in your browser.

The dashboard rescans automatically. To force an immediate refresh, click the status chip in the top-right corner.

## Notifications

Click the bell icon in the header to enable browser notifications. You will be prompted for permission on first enable. When the tab is in the background, a notification is fired for each newly discovered service.

The preference is stored in `localStorage` and persists across sessions.

## How It Works

1. **Port discovery** — `psutil.net_connections()` enumerates all `LISTEN` TCP sockets bound to `127.0.0.1`, `::1`, `0.0.0.0`, or `::`. On macOS systems where that requires root, `lsof` is used as a fallback.
2. **HTTP probing** — each port is probed with a `GET` request (1.5 s timeout, redirects followed). Ports that return a 2xx HTML response are classified as web services; all others go to "Other Services".
3. **Metadata extraction** — a lightweight HTML parser pulls `<title>`, `<meta name="description">`, and the favicon `<link>` from the first 32 KB of the response.
4. **Rendering** — a single-page app polls `/api/services` and re-renders only when the set of ports changes.

## Known Services

The following ports and process names are recognised and given friendly names automatically:

| Port | Service | Port | Service |
|------|---------|------|---------|
| 80 | HTTP Server | 5432 | PostgreSQL |
| 3000 | React Dev Server | 6379 | Redis |
| 3306 | MySQL | 8000 | Dev Server |
| 5000 | Flask | 8080 | HTTP Server |
| 5173 | Vite | 8888 | Jupyter |
| 5500 | Live Server | 27017 | MongoDB |

Process names (`node`, `python`, `nginx`, `postgres`, `redis-server`, etc.) are also matched when no port rule applies.

## Configuration

| Constant | Default | Description |
|----------|---------|-------------|
| `APP_PORT` | `5001` | Port the dashboard itself listens on |

## Project Structure

```
localhost-explorer/
├── app.py              # Flask app & service discovery logic
├── requirements.txt
└── templates/
    └── index.html      # Single-file frontend (HTML + CSS + JS)
```

## Author

**Ido Homri**
[ido@idohomri.io](mailto:ido@idohomri.io) · [idohomri.io](https://idohomri.io/)

## License

MIT © [Ido Homri](https://idohomri.io/)
