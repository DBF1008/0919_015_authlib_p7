#!/bin/sh
# Run the authlib unit test suites.
#
# Usage:
#   ./test.sh              # run core + jose unit tests
#   TESTPATH=tests/jose ./test.sh   # run a specific path
#
# Override the interpreter with the PYTHON environment variable, e.g.:
#   PYTHON=/path/to/python ./test.sh
set -e

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
TESTPATH="${TESTPATH:-tests/core tests/jose}"

exec "$PYTHON" -m pytest $TESTPATH "$@"
