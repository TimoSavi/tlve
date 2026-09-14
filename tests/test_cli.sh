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

# Test config with CRLF line endings and print definition without value=
TMP_CRLF=$(mktemp)
cat << 'EOF' | sed -e 's/$/\r/' > "$TMP_CRLF"
tl name=ber tag=ber length=ber
print name=call constructor="%n {\n" constructor-end="}\n"
structure name=test content-tl=ber
tlv name=item tag=1
structure-end
EOF
TMP_DAT=$(mktemp)
printf '\x01\x01\x42' > "$TMP_DAT"
"$TLVE" -c "$TMP_CRLF" -s test -p call "$TMP_DAT" > /dev/null
rm -f "$TMP_CRLF" "$TMP_DAT"

# Test TLVEOPEN preprocessor with gzip compression and quotes in template
if command -v gzip > /dev/null 2>&1; then
    TMP_DAT=$(mktemp)
    printf '\x01\x01\x42' > "$TMP_DAT"
    gzip "$TMP_DAT"
    TMP_RC=$(mktemp)
    cat << 'EOF' > "$TMP_RC"
tl name=ber tag=ber length=ber
print name=default value="%n=%v\n"
structure name=test content-tl=ber
tlv name=item tag=1
structure-end
EOF
    TLVEOPEN="gzip -dc \"%s\"" "$TLVE" -c "$TMP_RC" -s test "$TMP_DAT.gz" > /dev/null
    rm -f "$TMP_DAT.gz" "$TMP_RC"
fi

exit 0
