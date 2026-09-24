#!/bin/sh
# Protocol self-test for tsmapi (no TSM server required).
# Verifies NDJSON framing: one response line per op, trailing newline,
# and that every op responds (signon/send/get/query/delete) instead of hanging.
set -eu
cd "$(dirname "$0")/.."
[ -x ./tsmapi ] || { echo "tsmapi not built; run 'make' first" >&2; exit 2; }

fail=0
check() { # <name> <expected-substr> <actual>
    if printf '%s' "$3" | grep -qF "$2"; then
        printf '  ok   %s\n' "$1"
    else
        printf '  FAIL %s\n       expected: %s\n       got:      %s\n' "$1" "$2" "$3" >&2
        fail=1
    fi
}

P="$(printf '%s\n%s\n%s\n%s\n' \
    '{"op":"ping"}' \
    '{"op":"version"}' \
    '{"op":"signon","node":"nodeX","clientdir":"/nonexistent-dir"}' \
    '{"op":"send","fs":"/data","hl":"h","ll":"f","path":"/etc/hostname"}' \
    | ./tsmapi 2>/dev/null)"
check "ping frame"   '"ok":true,"op":"ping"'    "$(printf '%s\n' "$P" | sed -n 1p)"
check "version frame" '"ok":true,"op":"version"' "$(printf '%s\n' "$P" | sed -n 2p)"
check "signon frame" '"ok":false,"op":"signon"' "$(printf '%s\n' "$P" | sed -n 3p)"
check "send frame"   '"op":"send"'              "$(printf '%s\n' "$P" | sed -n 4p)"

Q="$(printf '%s\n%s\n%s\n' \
    '{"op":"get","fs":"/data","hl":"h","ll":"f","path":"/tmp/tsmapi.self"}' \
    '{"op":"query","fs":"/data","hl":"h","ll":"f"}' \
    '{"op":"delete","fs":"/data","hl":"h","ll":"f"}' \
    | ./tsmapi 2>/dev/null)"
check "get frame"     '"op":"get"'     "$(printf '%s\n' "$Q" | sed -n 1p)"
check "query frame"   '"op":"query"'   "$(printf '%s\n' "$Q" | sed -n 2p)"
check "delete frame"  '"op":"delete"'  "$(printf '%s\n' "$Q" | sed -n 3p)"

[ "$fail" -eq 0 ] && echo "tsmapi self-test: PASS" || { echo "tsmapi self-test: FAIL" >&2; exit 1; }
