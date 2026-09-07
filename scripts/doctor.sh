#!/bin/sh
set -eu

failed=0

check_command() {
  name=$1
  if command -v "$name" >/dev/null 2>&1; then
    printf '%-12s %s\n' "$name" "OK"
  else
    printf '%-12s %s\n' "$name" "MISSING"
    failed=1
  fi
}

for name in git docker node corepack pnpm uv make jq curl python3 openssl; do
  check_command "$name"
done

if command -v node >/dev/null 2>&1; then
  node_major=$(node -p 'process.versions.node.split(".")[0]')
  node_minor=$(node -p 'process.versions.node.split(".")[1]')
  if [ "$node_major" != "22" ] || [ "$node_minor" -lt 13 ]; then
    echo "Node.js >=22.13 <23 required; current=$(node --version)"
    failed=1
  fi
fi

if command -v uv >/dev/null 2>&1; then
  if ! uv python find 3.12 >/dev/null 2>&1; then
    echo "Python 3.12 is not available through uv"
    failed=1
  fi
fi

if command -v docker >/dev/null 2>&1 && ! docker info >/dev/null 2>&1; then
  echo "Docker CLI is installed but the Docker daemon is not running"
  failed=1
fi

if command -v docker >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required"
  failed=1
fi

exit "$failed"
