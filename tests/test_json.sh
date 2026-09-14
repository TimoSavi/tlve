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

# Skip test if JSON support was disabled at compile time
if ! "$TLVE" -j /dev/null > /dev/null 2>&1; then
    OUTPUT=$("$TLVE" -j /dev/null 2>&1 || true)
    case "$OUTPUT" in
        *"JSON output is not supported"*)
            echo "Skipping: JSON output support not enabled at compile time"
            exit 77
            ;;
    esac
fi

# 1. Definite length BER sequence to JSON Lines (-j)
printf '\x30\x0a\x02\x01\x2a\x04\x05hello' | "$TLVE" -j -c "$BER_RC" -s BER -o "$TMP_OUT"
grep -q '"name":"Sequence"' "$TMP_OUT"
grep -q '"name":"Integer"' "$TMP_OUT"
grep -q '"value":"42"' "$TMP_OUT"
grep -q '"name":"OctetString"' "$TMP_OUT"
grep -q '"value":"68656c6c6f"' "$TMP_OUT"
grep -q '"type":"constructed"' "$TMP_OUT"
grep -q '"children":\[' "$TMP_OUT"

# 2. Pretty-printed JSON output (-J / --pretty)
printf '\x30\x0a\x02\x01\x2a\x04\x05hello' | "$TLVE" -J -c "$BER_RC" -s BER -o "$TMP_OUT"
grep -q '"name": "Sequence"' "$TMP_OUT" || grep -q '"name":"Sequence"' "$TMP_OUT"
grep -q '"children": \[' "$TMP_OUT" || grep -q '"children":\[' "$TMP_OUT"

# 3. Indefinite length BER sequence to JSON
printf '\x30\x80\x02\x01\x2a\x00\x00' | "$TLVE" -j -c "$BER_RC" -s BER -o "$TMP_OUT"
grep -q '"form":"indefinite"' "$TMP_OUT"
grep -q '"name":"Integer"' "$TMP_OUT"
grep -q '"value":"42"' "$TMP_OUT"

# 4. Multi-record JSON Lines streaming (two top-level sequences)
printf '\x30\x03\x02\x01\x2a\x30\x03\x02\x01\x63' | "$TLVE" -j -c "$BER_RC" -s BER -o "$TMP_OUT"
LINE_COUNT=$(wc -l < "$TMP_OUT")
if [ "$LINE_COUNT" -ne 2 ]; then
    echo "Expected 2 JSON lines, got $LINE_COUNT" >&2
    exit 1
fi
grep -q '"value":"42"' "$TMP_OUT"
grep -q '"value":"99"' "$TMP_OUT"

# 5. JSON with expression filtering
printf '\x30\x03\x02\x01\x2a\x30\x03\x02\x01\x63' | "$TLVE" -j -c "$BER_RC" -s BER -e Integer=99 -o "$TMP_OUT"
grep -q '"value":"99"' "$TMP_OUT"
if grep -q '"value":"42"' "$TMP_OUT"; then
    echo "Expression filter failed to exclude unmatched record in JSON mode" >&2
    exit 1
fi

exit 0
