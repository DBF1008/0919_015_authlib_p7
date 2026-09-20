#!/bin/sh
# Manually run all Authlib unit test suites.
#
# Usage:
#   ./test.sh            # run every suite with the default python
#   PYTHON=python3.12 ./test.sh
#   ./test.sh tests/jose # run only the given suite(s)
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python}"

if [ $# -gt 0 ]; then
    suites="$@"
else
    suites="tests/core tests/jose tests/clients tests/flask tests/django"
fi

status=0
for suite in $suites; do
    echo "=== $suite ==="
    "$PYTHON" -m pytest "$suite" || status=1
done

if [ $status -eq 0 ]; then
    echo "ALL SUITES PASSED"
else
    echo "SOME SUITES FAILED"
fi
exit $status
