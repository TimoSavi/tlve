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

if [ -n "$top_srcdir" ] && [ -f "$top_srcdir/examples/binary.rc" ]; then
    BIN_RC="$top_srcdir/examples/binary.rc"
elif [ -f "./examples/binary.rc" ]; then
    BIN_RC="./examples/binary.rc"
elif [ -f "../examples/binary.rc" ]; then
    BIN_RC="../examples/binary.rc"
else
    echo "Cannot find binary.rc" >&2
    exit 1
fi

TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_OUT"' EXIT

# Tag: 2000 (0x07d0), Length: 4 (0x0004), Value: 0x01 0x02 0x03 0x04
printf '\x07\xd0\x00\x04\x01\x02\x03\x04' | "$TLVE" -c "$BIN_RC" -s bin -o "$TMP_OUT"

grep -q "\[2000\] = <01020304>" "$TMP_OUT"

exit 0
