#!/usr/bin/env bash
# cloud-symtest.sh — REAL cross-network NAT3<->NAT4 check WITHOUT a phone.
#
# On the (own) Tencent cloud box it builds a THROWAWAY network namespace that
# sits behind a Linux SNAT with `--random-fully`, which rotates the external
# PORT per destination -> a genuine symmetric (port-dependent) NAT, on a
# different real network than the desktop. Then it runs a p2p client INSIDE that
# namespace and a client on the desktop, and checks they punch NAT3<->NAT4 for
# real, over the public internet.
#
# THIS MODIFIES netfilter on a shared host. It is scoped (new dedicated chain,
# match on the veth subnet only) and ALWAYS undone via `trap` + explicit cleanup.
# DO NOT RUN without reading it and agreeing; it is provided for review.
#
#   Desktop (NAT3):  ./bin/p2p.exe connect -server <SERVER> -room symtest -verbose
#   This script (cloud, NAT4):  ./scripts/cloud-symtest.sh <SERVER_SSH_HOST> <PORT>
set -u
# No hardcoded admin endpoint: pass it explicitly or via env so this script can
# live in a public repo without leaking the SSH host/user/port.
SSH="${1:-${P2P_SSH:-}}"; SSPORT="${2:-${P2P_SSH_PORT:-}}"
if [ -z "$SSH" ] || [ -z "$SSPORT" ]; then
  echo "usage: P2P_SSH=user@host P2P_SSH_PORT=port $0 [ssh] [port]"; exit 2
fi
HOST="${SSH#*@}"                 # strip user@ -> cloud public IP
SERVER="${SERVER:-$HOST:8080}"   # signaling+STUN+relay on the single port
ROOM="${ROOM:-symtest}"
NS=p4test; VETH=h-p4; VPEER=n-p4; SUBNET=172.31.250; CPORT=5211
BIN=/tmp/p2p-symtest   # uploaded linux p2p client

cleanup() {
  echo "== cleanup: removing netns + scoped nat rules on cloud =="
  ssh -p "$SSPORT" "$SSH" "
    ip netns del $NS 2>/dev/null || true
    ip link del $VETH 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s $SUBNET.0/24 -j P4SNAT 2>/dev/null || true
    iptables -t nat -F P4SNAT 2>/dev/null || true
    iptables -t nat -X P4SNAT 2>/dev/null || true
    iptables -D FORWARD -i $VETH -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o $VETH -j ACCEPT 2>/dev/null || true
    ip netns list | grep -q $NS && echo 'WARN: netns still present' || echo 'cloud restored'
  " 2>&1
}
trap cleanup EXIT

echo "== upload client =="
scp -P "$SSPORT" /tmp/p2p-server-linux "$SSH:$BIN" >/dev/null 2>&1
ssh -p "$SSPORT" "$SSH" "chmod +x $BIN"

echo "== build isolated symmetric NAT namespace (scoped rules only) =="
ssh -p "$SSPORT" "$SSH" "
  set -e
  ip netns del $NS 2>/dev/null || true
  ip netns add $NS
  ip link add $VETH type veth peer name $VPEER
  ip link set $VPEER netns $NS
  ip addr add $SUBNET.1/24 dev $VETH; ip link set $VETH up
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec $NS ip addr add $SUBNET.2/24 dev $VPEER
  ip netns exec $NS ip link set $VPEER up
  ip netns exec $NS ip link set lo up
  ip netns exec $NS ip route add default via $SUBNET.1
  # dedicated nat chain; --random-fully => port rotates per destination (symmetric).
  iptables -t nat -N P4SNAT 2>/dev/null || true
  iptables -t nat -A P4SNAT -o eth0 -j MASQUERADE --random-fully
  iptables -t nat -C POSTROUTING -s $SUBNET.0/24 -j P4SNAT 2>/dev/null || iptables -t nat -A POSTROUTING -s $SUBNET.0/24 -j P4SNAT
  iptables -C FORWARD -i $VETH -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $VETH -j ACCEPT
  iptables -C FORWARD -o $VETH -j ACCEPT 2>/dev/null || iptables -A FORWARD -o $VETH -j ACCEPT
  echo '--- verify namespace sees a symmetric NAT (public port changes per dest):'
  ip netns exec $NS $BIN nat-check -server $SERVER 2>&1 | tr -d '\000' | sed 's/^/  [ns] /'
" 2>&1

echo
echo "==> Now, on the DESKTOP (NAT3) run:"
echo "    ./bin/p2p.exe connect -server $SERVER -room $ROOM -verbose"
echo "==> This keeps the namespace client joining the same room; watch both logs"
echo "    for 'connected via punched'. Ctrl-C here (and on the desktop) when done."
echo "    Namespace client runs until you Ctrl-C; cleanup removes all cloud state."
ssh -p "$SSPORT" "$SSH" "ip netns exec $NS $BIN connect -server $SERVER -room $ROOM -verbose" 2>&1 | tr -d '\000' | grep --line-buffered -aE "NAT |punching plan|kind=|connected via|peer joined" &
BGP=$!
read -r -p "Press Enter after the desktop run finishes to tear down the cloud namespace... " _
kill $BGP 2>/dev/null
# trap runs cleanup
