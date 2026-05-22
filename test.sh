#!/usr/bin/env bash
# test.sh — validate the godns nameserver against a running instance.
#
# Usage:
#   ./test.sh [host] [port]
# Defaults: 127.0.0.1 15353
#
# Start the server first, e.g.:
#   go run ./src                 # listens on :15353
#   go run ./src -addr 127.0.0.1:15353

set -u

HOST="${1:-127.0.0.1}"
PORT="${2:-15353}"

pass=0
fail=0

if ! command -v dig >/dev/null 2>&1; then
  echo "dig is required" >&2
  exit 2
fi

green='\033[0;32m'
red='\033[0;31m'
reset='\033[0m'

# run <name> <qname> <qtype> <expect-status> [answer-regex]
run() {
  local name="$1" qname="$2" qtype="$3" want_status="$4" want_re="${5:-}"
  local out status ok=1

  out=$(dig +tries=1 +time=2 +noall +answer +authority +comments \
        @"$HOST" -p "$PORT" "$qname" "$qtype" 2>&1)
  status=$(printf '%s\n' "$out" | awk -F'status: ' '
    /status:/ { split($2, a, ","); print a[1]; exit }
  ')

  [[ "$status" == "$want_status" ]] || ok=0
  if [[ -n "$want_re" ]] && ! printf '%s\n' "$out" | grep -Eq "$want_re"; then
    ok=0
  fi

  if (( ok )); then
    printf "${green}PASS${reset}  %-22s %-22s %-5s -> %s\n" "$name" "$qname" "$qtype" "$status"
    pass=$((pass+1))
  else
    printf "${red}FAIL${reset}  %-22s %-22s %-5s\n" "$name" "$qname" "$qtype"
    printf "      expected status=%s" "$want_status"
    [[ -n "$want_re" ]] && printf " grep=%s" "$want_re"
    printf "\n      got status=%s\n" "${status:-<none>}"
    printf '      dig output:\n%s\n' "$out" | sed 's/^/        /'
    fail=$((fail+1))
  fi
}

# aa_flag_check <name> <qname> <qtype>
aa_flag_check() {
  local name="$1" qname="$2" qtype="$3"
  local out flags ok=1
  out=$(dig +tries=1 +time=2 +noall +comments \
        @"$HOST" -p "$PORT" "$qname" "$qtype" 2>&1)
  flags=$(printf '%s\n' "$out" | awk -F'flags: ' '/flags:/ { split($2, a, ";"); print a[1]; exit }')
  if [[ "$flags" == *"aa"* ]]; then
    printf "${green}PASS${reset}  %-22s aa-flag set (%s)\n" "$name" "$flags"
    pass=$((pass+1))
  else
    printf "${red}FAIL${reset}  %-22s aa-flag missing (flags='%s')\n" "$name" "$flags"
    fail=$((fail+1))
  fi
}

echo "Testing godns at $HOST:$PORT"
echo "----------------------------------------------------------------"

run "SOA apex"         "godns.co.za"          SOA   NOERROR  "ns1\\.godns\\.co\\.za\\..*hostmaster"
run "NS apex"          "godns.co.za"          NS    NOERROR  "ns[12]\\.godns\\.co\\.za"
run "A apex"           "godns.co.za"          A     NOERROR  "192\\.0\\.2\\.1$"
run "AAAA apex"        "godns.co.za"          AAAA  NOERROR  "2001:db8::1"
run "MX apex"          "godns.co.za"          MX    NOERROR  "10 mail\\.godns\\.co\\.za"
run "TXT apex"         "godns.co.za"          TXT   NOERROR  "v=spf1"
run "A www"            "www.godns.co.za"      A     NOERROR  "192\\.0\\.2\\.2"
run "A ns1 (glue)"     "ns1.godns.co.za"      A     NOERROR  "192\\.0\\.2\\.10"
run "A ns2 (glue)"     "ns2.godns.co.za"      A     NOERROR  "192\\.0\\.2\\.11"
run "A mail"           "mail.godns.co.za"     A     NOERROR  "192\\.0\\.2\\.20"
run "NODATA AAAA www"  "www.godns.co.za"      AAAA  NOERROR  "SOA"
run "NXDOMAIN child"   "missing.godns.co.za"  A     NXDOMAIN "SOA"
run "REFUSED out-zone" "example.com"          A     REFUSED

aa_flag_check         "AA on apex A"          "godns.co.za"          A

echo "----------------------------------------------------------------"
echo "Passed: $pass    Failed: $fail"
(( fail == 0 ))
