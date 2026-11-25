#!/bin/bash

#
# (C) BSDv2
#

#
# Description:
# Runs the tests. Every t/test_*.py is a suite, it starts its own nginx.
#
#   ./t/run.sh                     all suites
#   ./t/run.sh foreground          the suites whose file names contain "foreground"
#   TEST="crash host" ./t/run.sh   only the tests whose names contain "crash" or "host"
#
# NGINX_BIN   nginx built with the module, ./nginx/objs/nginx by default
#
# The rest of the environment is described in t/harness.py.
#

set -u
set -o pipefail

cd "$(dirname "$0")/.." || exit 2

NGINX_BIN=${NGINX_BIN:-$(pwd)/nginx/objs/nginx}
export NFP_NGINX_BIN="$NGINX_BIN"

if [ ! -x "$NGINX_BIN" ]; then
  echo "nginx binary $NGINX_BIN not found, build it first: make build" >&2
  exit 2
fi

mkdir -p t/.run

suites=0
failed=0

for suite in t/test_*.py; do
  if [ $# -gt 0 ]; then
    selected=0
    for name in "$@"; do
      case "$suite" in *"$name"*) selected=1 ;; esac
    done
    [ "$selected" = 1 ] || continue
  fi

  log=t/.run/$(basename "$suite" .py).log
  suites=$((suites + 1))

  # TEST is a list of test name fragments, one per argument
  # shellcheck disable=SC2086
  python3 "$suite" ${TEST:-} 2>&1 | tee "$log"
  if [ $? -ne 0 ]; then
    failed=$((failed + 1))
  fi
done

if [ "$suites" -eq 0 ]; then
  echo "no test suite matches: $*" >&2
  exit 2
fi

if [ "$failed" -eq 0 ]; then
  echo "all $suites suites passed"
else
  echo "$failed of $suites suites failed, the logs are in t/.run/"
fi

[ "$failed" -eq 0 ]

# vi:set ft=sh ts=2 sw=2 et:
