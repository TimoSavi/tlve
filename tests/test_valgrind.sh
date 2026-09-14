#!/bin/sh
set -e

if ! command -v valgrind > /dev/null 2>&1; then
    echo "Valgrind not found, skipping memory leak test"
    exit 77
fi

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

if [ -n "$top_srcdir" ] && [ -d "$top_srcdir/examples" ]; then
    EXDIR="$top_srcdir/examples"
elif [ -d "./examples" ]; then
    EXDIR="./examples"
elif [ -d "../examples" ]; then
    EXDIR="../examples"
else
    echo "Cannot find examples directory" >&2
    exit 1
fi

VG="valgrind -q --error-exitcode=1 --leak-check=full --show-leak-kinds=all"

# 1. Version and help
$VG "$TLVE" -h > /dev/null
$VG "$TLVE" -V > /dev/null

# 2. BER stream
printf '\x30\x0a\x02\x01\x2a\x04\x05hello\x30\x80\x02\x01\x07\x00\x00' | $VG "$TLVE" -c "$EXDIR/ber.rc" -s BER -o /dev/null

# 3. Binary stream
printf '\x07\xd0\x00\x04\x01\x02\x03\x04' | $VG "$TLVE" -c "$EXDIR/binary.rc" -s bin -o /dev/null

# 4. TAP3 stream
printf '\x61\x05\x64\x03\x02\x01\x05' | $VG "$TLVE" -c "$EXDIR/tap_3_11.rc" -s tap311 -o /dev/null

# 5. JSON Lines stream
printf '\x30\x0a\x02\x01\x2a\x04\x05hello\x30\x80\x02\x01\x07\x00\x00' | $VG "$TLVE" -j -c "$EXDIR/ber.rc" -s BER -o /dev/null

# 6. JSON Pretty stream
printf '\x30\x0a\x02\x01\x2a\x04\x05hello' | $VG "$TLVE" -J -c "$EXDIR/ber.rc" -s BER -o /dev/null

exit 0
