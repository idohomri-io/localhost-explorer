#!/usr/bin/env bash
# Runs localhost-explorer from the published image.
#
# --net=host is REQUIRED on Linux: it makes the container share the host's
# network namespace so psutil/lsof can see the host's listening ports and
# HTTP probes reach http://localhost:<port> on the host.
#
# --net=host is NOT supported on macOS / Windows Docker Desktop (the container
# runs inside a Linux VM and cannot see the Mac/Windows host's ports).
# Use the local Python install instead on those platforms:
#   pip install -r requirements.txt && python app.py
set -euo pipefail

IMAGE="${1:-ghcr.io/idohomri-io/localhost-explorer:v1.0.0}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: --net=host only works on Linux."
  echo "Run the app directly instead:"
  echo "  pip install -r requirements.txt && python app.py"
  exit 1
fi

echo "Starting localhost-explorer at http://localhost:5001"
docker run --rm \
  --net=host \
  --name localhost-explorer \
  "$IMAGE"
