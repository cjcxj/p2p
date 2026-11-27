#!/usr/bin/env bash
# nat34-check.sh — measure pure-direct NAT3(port-restricted cone) <-> NAT4(symmetric)
# hole-punch success across real networks using a single signaling server.
#
# Usage:
#   ./scripts/nat34-check.sh -s 1.2.3.4:8080 -r demo -n 10 \
#       -b ./bin/p2p-linux \
#       --stuns "stun.miwifi.com:3478,stun.chat.bilibili.com:3478"
set -u

SERVER="" ROOM="demo" TRIALS=10 MAXW=25 BIN="./bin/p2p-linux" STUNS="" SPRAY="" SOCKETS="" PPS="1500"
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
    --pps) PPS="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

if [ -z "$SERVER" ]; then echo "need -s <server:port>"; exit 2; fi
if [ ! -x "$BIN" ] && ! command -v "$BIN" >/dev/null 2>&1; then
  echo "p2p binary not found/executable: $BIN"; exit 2
fi

OUT="nat34-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

echo "=== local NAT + candidate enumeration (this network) ==="
"$BIN" nat-check -server "$SERVER" ${STUNS:+-stun-list "$STUNS"} 2>&1 \
  | tr -d '\000' \
  | grep -aE "NAT type|public|egressIPs|egressPool|port step|port preserve|PBA block|IPv6|UPnP|evidence" \
  | sed 's/^/  /'
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
  [ -n "$PPS" ]     && args+=(-punch-pps "$PPS")
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
  hit=$(grep -oE "from [^ ]+ -> connected via punched" "$log" 2>/dev/null | head -1 | sed -E 's/ ->.*//')
  [ "$status" = punched ] && pass=$((pass+1))
  [ -n "$ttp" ] && times="$times $ttp"
  [ -n "$hit" ] && hitips="$hitips\"$hit\""
  echo "trial $i: room=$room | $status ${ttp:+(${ttp}s)} | local=$nat | win-hit=$hit"
  kill $pid 2>/dev/null; killbin; sleep 1
done

echo "======================================================"
echo "Pure-direct NAT3<->NAT4 punch success: $pass/$TRIALS"
[ -n "$times" ] && echo "time-to-direct (s):$times"
[ -n "$hitips" ] && echo "winning peer addresses:$hitips"
echo "logs saved in $OUT/"
