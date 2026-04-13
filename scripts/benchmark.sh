#!/bin/bash
# piilex benchmark: generate a synthetic monorepo and measure scan performance.
#
# Usage:
#   bash scripts/benchmark.sh [file_count]
#
# Default: 1000 files. Set to 10000+ for stress testing.

set -euo pipefail

FILE_COUNT="${1:-1000}"
BENCH_DIR=$(mktemp -d)
trap "rm -rf $BENCH_DIR" EXIT

echo "=== piilex Benchmark ==="
echo "  Files:      $FILE_COUNT"
echo "  Directory:  $BENCH_DIR"
echo ""

# Generate synthetic TypeScript files
echo "Generating $FILE_COUNT test files..."
for i in $(seq 1 "$FILE_COUNT"); do
  dir="$BENCH_DIR/src/module_$((i % 50))"
  mkdir -p "$dir"
  cat > "$dir/file_${i}.ts" << 'TSEOF'
import { Logger } from './logger';

interface UserData {
  email: string;
  fullName: string;
  phoneNumber: string;
  ipAddress: string;
}

const logger = new Logger();

export function processUser(user: UserData) {
  logger.info(`Processing user: ${user.email}`);
  const password = getPassword();
  db.save({ email: user.email, name: user.fullName });
  fetch("https://api.example.com/track", {
    method: "POST",
    body: JSON.stringify({ email: user.email }),
  });
}

function getPassword(): string {
  return process.env.DB_PASSWORD || "";
}
TSEOF
done

# Also generate some clean files (no PII)
for i in $(seq 1 $((FILE_COUNT / 5))); do
  dir="$BENCH_DIR/src/utils"
  mkdir -p "$dir"
  cat > "$dir/util_${i}.ts" << 'TSEOF'
export function add(a: number, b: number): number {
  return a + b;
}
export function format(value: number): string {
  return value.toFixed(2);
}
TSEOF
done

TOTAL_FILES=$((FILE_COUNT + FILE_COUNT / 5))
echo "  Generated: $TOTAL_FILES files"
echo ""

# Find piilex binary
PIILEX="${PIILEX:-piilex}"
if [ ! -f "$PIILEX" ]; then
  PIILEX="target/release/piilex"
fi
if [ ! -f "$PIILEX" ]; then
  PIILEX="target/debug/piilex"
fi
echo "Binary: $PIILEX"
"$PIILEX" --version
echo ""

# Warmup
echo "Warmup..."
"$PIILEX" scan "$BENCH_DIR" -q 2>&1 > /dev/null

# Benchmark: sequential-like (small batches)
echo ""
echo "=== Benchmark: Full scan ==="
time "$PIILEX" scan "$BENCH_DIR" -q 2>&1

echo ""
echo "=== Benchmark: JSON output ==="
time "$PIILEX" scan "$BENCH_DIR" -o json -q 2>/dev/null | wc -c
echo "bytes JSON output"

echo ""
echo "=== Benchmark: --no-flow (fast mode) ==="
time "$PIILEX" scan "$BENCH_DIR" --no-flow -q 2>&1

echo ""
echo "=== Memory usage ==="
if command -v /usr/bin/time &> /dev/null; then
  /usr/bin/time -v "$PIILEX" scan "$BENCH_DIR" -q 2>&1 | grep "Maximum resident" || true
else
  echo "(GNU time not available, skipping memory measurement)"
fi

echo ""
echo "=== Done ==="
