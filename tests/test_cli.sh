#!/bin/sh
set -e

if [ -n "$top_builddir" ] && [ -x "$top_builddir/src/tlve" ]; then
    TLVE="$top_builddir/src/tlve"
elif [ -x "./src/tlve" ]; then
    TLVE="./src/tlve"
elif [ -x "../src/tlve" ]; then
    TLVE="../src/tlve"
else
    echo "Cannot find tlve executable" >&2
    exit 1
fi

# Test -h / --help exits with 0
"$TLVE" -h > /dev/null
"$TLVE" --help > /dev/null

# Test -V / --version exits with 0
"$TLVE" -V > /dev/null
"$TLVE" --version > /dev/null

# Test invalid option exits with non-zero
if "$TLVE" -Z > /dev/null 2>&1; then
    echo "Expected tlve -Z to fail" >&2
    exit 1
fi

# Test non-existent config file exits with non-zero
if "$TLVE" -c /nonexistent/path/to/rcfile -o /dev/null /dev/null > /dev/null 2>&1; then
    echo "Expected non-existent config to fail" >&2
    exit 1
fi

exit 0
