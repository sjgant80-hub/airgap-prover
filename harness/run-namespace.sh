#!/usr/bin/env bash
# run-namespace.sh — run a workload as a GUEST in a locked network namespace and
# WITNESS its packets FROM BELOW (the host side of the veth). Linux only.
#
# The guest gets its own netns with a veth pair to the host and a default route,
# so it CAN try to reach out — but the host does NOT forward or NAT, so anything
# it sends dies at the boundary. tcpdump on the HOST side records every packet
# that crossed the boundary; the kernel (cli.mjs) renders the egress verdict.
# The guest cannot edit packets the host already captured — that is the point.
#
# Usage: sudo ./harness/run-namespace.sh <offline|phonehome> <outdir>
set -euo pipefail

MODE="${1:?usage: run-namespace.sh <offline|phonehome> <outdir>}"
OUT="${2:?usage: run-namespace.sh <offline|phonehome> <outdir>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$OUT"

NS=agp
HOST_VETH=agp-host
NS_VETH=agp-ns
HOST_IP=10.9.9.1
NS_IP=10.9.9.2
PFX=24

cleanup() {
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$HOST_VETH" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# Make sure the host will NOT forward the guest's packets anywhere real.
sysctl -w net.ipv4.ip_forward=0 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null || true

# Build the locked boundary: a veth pair, one end in the guest netns.
ip netns add "$NS"
ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
ip link set "$NS_VETH" netns "$NS"
ip addr add "$HOST_IP/$PFX" dev "$HOST_VETH"
ip link set "$HOST_VETH" up
ip netns exec "$NS" ip addr add "$NS_IP/$PFX" dev "$NS_VETH"
ip netns exec "$NS" ip link set "$NS_VETH" up
ip netns exec "$NS" ip link set lo up
# A default route so a phone-home SYN is actually EMITTED onto the veth (where we
# can see it). It still cannot reach the internet — the host won't forward it.
ip netns exec "$NS" ip route add default via "$HOST_IP"

PCAP="$OUT/$MODE.pcap"
echo "[harness] capturing on host side of $HOST_VETH -> $PCAP"
# -U: packet-buffered (flush each packet). Capture IPv4 + IPv6, skip ARP.
tcpdump -i "$HOST_VETH" -w "$PCAP" -U -n '(ip or ip6)' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1  # let tcpdump attach before the workload runs

case "$MODE" in
  offline)   WORKLOAD="$REPO/workloads/offline-grow.mjs" ;;
  phonehome) WORKLOAD="$REPO/workloads/phone-home.mjs" ;;
  *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac

echo "[harness] running $MODE workload inside netns $NS"
ip netns exec "$NS" node "$WORKLOAD" || true  # the workload's own exit is not the verdict
sleep 1  # let the last packets flush

kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
echo "[harness] captured $(stat -c%s "$PCAP" 2>/dev/null || echo 0) bytes"
