#!/usr/bin/env bash
# nat34-check.sh — measure NAT3(port-restricted cone) <-> NAT4(symmetric) hole-punch
# success across ANY two networks, on a SINGLE signaling server.
#
# Run this on BOTH machines at the same time, pointing at the same --server and
# the same --room base. Each machine reports its own NAT type, whether it reached
# a DIRECT punched link (vs relay), time-to-direct, and the peer address/ports
# that actually won -- which shows whether the multi-STUN candidate set covered
# the peer-direction egress IP.
#
# The whole point of the configurable multi-STUN: --stun-list lets you add public
# observation points so the destination-rotating CGNAT candidate pool is
# enumerated. More diverse, reachable STUNs -> better coverage -> higher success
# on networks where a handful of IPs is not enough.
#
# Usage:
#   ./nat34-check.sh -s 1.2.3.4:8080 -r demo -n 10 \
#       -b ./bin/p2p \
#       --stuns "74.125.250.129:19302,111.206.174.2:3478,stun.miwifi.com:3478"
#
# -n trials  -w max-seconds-per-trial  --spray <ports/ip>  --sockets <pool>
set -u

SERVER="" ROOM="demo" TRIALS=10 MAXW=25 BIN="./bin/p2p" STUNS="" SPRAY="" SOCKETS=""
while [ $# -gt 0 ]; do
  case "$1" in
    -s) SERVER="$2"; shift 2;;
    -r) ROOM="$2"; shift 2;;
    -n) TRIALS="$2"; shift 2;;
    -w) MAXW="$2"; shift 2;;
    -b) BIN="$2"; shift 2;;
    --stuns) STUNS="$2"; shift 2;;
    --spray) SPRAY="$2"; shift 2;;
    --sockets) SOCKETS="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

if [ -z "$SERVER" ]; then echo "need -s <server:port>"; exit 2; fi
if [ ! -x "$BIN" ] && ! command -v "$BIN" >/dev/null 2>&1; then
  echo "p2p binary not found/executable: $BIN"; exit 2; fi

OUT="nat34-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

# Diagnostic preamble: how many candidate egress IPs does THIS network expose to
# the configured STUN observation points? A single candidate means either a cone
# (fine) or a rotating CGNAT that the current STUN list did NOT enumerate -- the
# latter is the #1 cause of NAT3<->NAT4 failing on a stubborn network; add more
# diverse --stuns until candidates > 1 and the egress is covered.
echo "=== local NAT + candidate enumeration (this network) ==="
"$BIN" nat-check -server "$SERVER" ${STUNS:+-stun-list "$STUNS"} 2>&1 | tr -d '\000' | grep -aE "NAT type|public|candidates|port step|evidence" | sed 's/^/  /'
echo

pass=0; times=""; hitips=""

killbin() { pkill -f "$(basename "$BIN") connect" 2>/dev/null || true; }

for i in $(seq 1 "$TRIALS"); do
  room="$ROOM-$i"
  log="$OUT/trial$i.log"
  killbin; sleep 1
  args=(connect -server "$SERVER" -room "$room" -verbose)
  [ -n "$STUNS" ]   && args+=(-stun-list "$STUNS")
  [ -n "$SPRAY" ]   && args+=(-sym-spray "$SPRAY")
  [ -n "$SOCKETS" ] && args+=(-punch-sockets "$SOCKETS")
  "$BIN" "${args[@]}" >"$log" 2>&1 &
  pid=$!

  start=$(date +%s); status="timeout"; ttp=""
  while [ $(( $(date +%s) - start )) -le "$MAXW" ]; do
    if grep -q "connected via punched" "$log" 2>/dev/null; then
      status="punched"; ttp=$(( $(date +%s) - start )); break
    fi
    sleep 1
  done

  nat=$(grep -oE "NAT [a-z_]+" "$log" 2>/dev/null | head -1)
  hit=$(grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+ -> connected via punched" "$log" 2>/dev/null | head -1 | sed -E 's/ ->.*//')
  ncan=$(grep -oE "candidate|candidates" "$log" 2>/dev/null | head -1)
  [ "$status" = punched ] && pass=$((pass+1))
  [ -n "$ttp" ] && times="$times $ttp"
  [ -n "$hit" ] && hitips="$hitips\"$hit\""

  echo "trial $i: room=$room | $status ${ttp:+(${ttp}s)} | local=$nat | win-hit=$hit"
  kill $pid 2>/dev/null; killbin; sleep 1
done

echo "======================================================"
echo "NAT3<->NAT4 punch success: $pass/$TRIALS"
[ -n "$times" ] && echo "time-to-direct (s):$times"
[ -n "$hitips" ] && echo "winning peer addresses:$hitips"
echo "logs in $OUT/  -- attach this dir when reporting a network to me."
echo "If success < N/N: add more reachable --stuns (diverse public IPs) so the"
echo "peer-direction egress IP is inside the candidate set; then re-run."
