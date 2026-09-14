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

# 1. Definite length BER sequence containing Integer (42) and OctetString ("hello")
# Integer: tag=0x02, len=0x01, val=0x2a (42)
# OctetString: tag=0x04, len=0x05, val="hello" (0x68 0x65 0x6c 0x6c 0x6f)
# Sequence: tag=0x30, len=0x0a (10 bytes)
printf '\x30\x0a\x02\x01\x2a\x04\x05hello' | "$TLVE" -c "$BER_RC" -s BER -o "$TMP_OUT"

grep -q "Integer=42" "$TMP_OUT"
grep -q "OctetString=68656c6c6f" "$TMP_OUT"
grep -q "Sequence" "$TMP_OUT"

# 2. Indefinite length BER sequence
# Sequence: tag=0x30, len=0x80 (indefinite), Integer (42), EOC (0x00 0x00)
printf '\x30\x80\x02\x01\x2a\x00\x00' | "$TLVE" -c "$BER_RC" -s BER -o "$TMP_OUT"

grep -q "Integer=42" "$TMP_OUT"
grep -q "Sequence" "$TMP_OUT"

exit 0
