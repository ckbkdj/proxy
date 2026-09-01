#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-newapi-risk-control}"
MOCK_CONTAINER="${PROJECT_NAME}-mock"
LOG_DIR="${RISKGATE_TEST_LOG_DIR:-/tmp/riskgate-integration}"
mkdir -p "$LOG_DIR"

cleanup() {
  docker rm -f "$MOCK_CONTAINER" >/dev/null 2>&1 || true
  (
    cd "$ROOT"
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -f .env
  )
}
trap cleanup EXIT

cleanup
cd "$ROOT"
cp .env.example .env
sed -i 's/^ALLOW_PRIVATE_UPSTREAMS=.*/ALLOW_PRIVATE_UPSTREAMS=true/' .env
sed -i 's#^PUBLIC_BASE_URL=.*#PUBLIC_BASE_URL=http://127.0.0.1:8080#' .env

docker compose up -d --build postgres redis riskgate

docker run -d \
  --name "$MOCK_CONTAINER" \
  --network "${PROJECT_NAME}_edge" \
  --mount "type=bind,src=$ROOT/tests/integration/mock_server.py,dst=/app/mock_server.py,readonly" \
  python:3.12-alpine \
  python /app/mock_server.py > /dev/null

set +e
python3 tests/integration/test_stack.py 2>&1 | tee "$LOG_DIR/test.log"
result=${PIPESTATUS[0]}
set -e

docker compose logs --no-color riskgate > "$LOG_DIR/riskgate.log" 2>&1 || true
docker logs "$MOCK_CONTAINER" > "$LOG_DIR/mock.log" 2>&1 || true

if (( result != 0 )); then
  echo "Integration test failed; logs: $LOG_DIR" >&2
  tail -n 200 "$LOG_DIR/riskgate.log" >&2 || true
  exit "$result"
fi

grep -q '"ok": true' "$LOG_DIR/test.log"
for forbidden in \
  'HTTP handler panic' \
  'admin audit write failed' \
  'trace batch PostgreSQL write failed' \
  'trace Redis DLQ write failed' \
  'migration failed'; do
  if grep -q "$forbidden" "$LOG_DIR/riskgate.log"; then
    echo "Unexpected service log entry: $forbidden" >&2
    exit 1
  fi
done

echo "RiskGate Docker integration checks passed."
