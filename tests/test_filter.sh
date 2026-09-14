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

if [ -n "$top_srcdir" ] && [ -f "$top_srcdir/examples/ber.rc" ]; then
    BER_RC="$top_srcdir/examples/ber.rc"
elif [ -f "./examples/ber.rc" ]; then
    BER_RC="./examples/ber.rc"
elif [ -f "../examples/ber.rc" ]; then
    BER_RC="../examples/ber.rc"
else
    echo "Cannot find ber.rc" >&2
    exit 1
fi

TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_OUT"' EXIT

INPUT='\x02\x01\x2a\x04\x05hello\x02\x01\x07'

# 1. Filter by name: -n Integer
printf "$INPUT" | "$TLVE" -c "$BER_RC" -s BER -n Integer -o "$TMP_OUT"
grep -q "Integer=42" "$TMP_OUT"
grep -q "Integer=7" "$TMP_OUT"
if grep -q "OctetString" "$TMP_OUT"; then
    echo "Expected OctetString to be filtered out" >&2
    exit 1
fi

# 2. Filter by expression: -e Integer=42
printf "$INPUT" | "$TLVE" -c "$BER_RC" -s BER -e Integer=42 -o "$TMP_OUT"
grep -q "Integer=42" "$TMP_OUT"
if grep -q "Integer=7" "$TMP_OUT"; then
    echo "Expected Integer=7 to be filtered out" >&2
    exit 1
fi

exit 0
