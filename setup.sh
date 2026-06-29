#!/usr/bin/env bash
# One-command RoeShare setup: writes a .env with a strong secret + admin
# password (if missing), then builds and starts the container.
#
#   bash setup.sh
#
# Override any value by exporting it first, e.g.:
#   PORT=8080 ADMIN_PASSWORD=hunter2 UPLOAD_PASSWORD=letmein bash setup.sh
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
	echo "Docker is not installed or not on PATH. Install Docker, then re-run." >&2
	exit 1
fi

rand() { openssl rand -hex "$1" 2>/dev/null || head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

if [ ! -f .env ]; then
	echo "Creating .env ..."
	PORT="${PORT:-3300}"
	ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(rand 9)}"
	SECRET="$(rand 32)"
	cat > .env <<EOF
HOST=0.0.0.0
PORT=$PORT
BASE_URL=${BASE_URL:-http://localhost:$PORT}
ADMIN_PASSWORD=$ADMIN_PASSWORD
UPLOAD_PASSWORD=${UPLOAD_PASSWORD:-}
SECRET=$SECRET
TRUST_PROXY=${TRUST_PROXY:-0}
EOF
	echo "  Wrote .env (admin password: $ADMIN_PASSWORD)"
else
	echo ".env already exists - keeping it."
fi

echo "Building and starting RoeShare ..."
docker compose up -d --build

BASE="$(grep -E '^BASE_URL=' .env | cut -d= -f2-)"
echo
echo "RoeShare is running."
echo "  App:   $BASE"
echo "  Admin: $BASE/admin   (password is ADMIN_PASSWORD in .env)"
echo "  Logs:  docker compose logs -f"
echo "  Stop:  docker compose down"
