#!/usr/bin/env bash
# Run a test case on two nodes (RFD 2, D5): build an image for node a and one for node b from
# this tree, boot both in QEMU next to the mock control plane (which also load-balances the data
# ports) and, if asked, tools/net-peer.py through that load balancer. Called by tests/run.sh for
# cases with NODES=2.
#
#   two-nodes.sh APP USER_FEATURES KERNEL_FEATURES LIMIT MAKEVARS...
#
# Node a serves data on 127.0.0.1:8080, node b on 8090; the load balancer listens on 8000.
# With UPDATE=1, node a's image is also built with SIGN_VERSION=2: when node a reboots (QEMU
# exits with status 0: -no-reboot), it boots again from that one, as an updated node would.
# Prints each node's serial output, then the peer's and the control plane's; exits with node
# a's last status.
set -u
cd "$(dirname "$0")/.."
app=$1 user=$2 kernel=$3 limit=$4
shift 4
vars=("$@")
cp="" peer="" update=""
for v in "${vars[@]}"; do
  [[ "$v" == CP=* ]] && cp=${v#CP=}
  [[ "$v" == PEER=* ]] && peer=${v#PEER=}
  [[ "$v" == UPDATE=1 ]] && update=1
done

# build NAME ISO-OUT MAKEVARS...: an image for one node, and the command to boot it.
build() {
  local node=$1 iso=$2
  shift 2
  if ! make -s image APP="tests/apps/$app.toml" USER_FEATURES="$user" KERNEL_FEATURES="$kernel" NODE="$node" "${vars[@]}" "$@" >build/two-nodes-build.log 2>&1; then
    echo "two-nodes: building node $node failed"
    cat build/two-nodes-build.log
    exit 2
  fi
  cp build/vanir-os.iso "$iso"
}
build a build/node-a.iso
qemu_a=$(make -s qemu-cmd "${vars[@]}" | sed "s|build/vanir-os.iso|build/node-a.iso|; s|build/telemetry.log|build/telemetry-a.log|")
if [ -n "$update" ]; then
  build a build/node-a-v2.iso SIGN_VERSION=2
fi
build b build/node-b.iso
qemu_b=$(make -s qemu-cmd "${vars[@]}" NET_PORT=8090 NET_MGMT_PORT=8091 | sed "s|build/vanir-os.iso|build/node-b.iso|; s|build/telemetry.log|build/telemetry-b.log|")

rm -f build/cp.log build/cp-telemetry.log build/peer.log build/node-a.out build/node-b.out
tools/control-plane.py "$cp" --timeout "$limit" --lb 8000 --backend a=8080 --backend b=8090 --linger "$limit" >build/cp.log 2>&1 &
cp_pid=$!
sleep 0.5
if [ -n "$peer" ]; then
  NET_PORT=8000 tools/net-peer.py "$peer" --timeout "$limit" >build/peer.log 2>&1 &
  peer_pid=$!
fi

# Node a, booting again from the updated image when it reboots.
(
  iso=build/node-a.iso
  while true; do
    timeout "$limit" $qemu_a >>build/node-a.out 2>&1
    status=$?
    if [ $status -eq 0 ] && [ -n "$update" ] && [ "$iso" = build/node-a.iso ]; then
      echo "--- node a rebooted; booting the updated image ---" >>build/node-a.out
      iso=build/node-a-v2.iso
      qemu_a=${qemu_a/build\/node-a.iso/build\/node-a-v2.iso}
      continue
    fi
    echo $status >build/node-a.status
    break
  done
) &
a_pid=$!
timeout "$limit" $qemu_b >build/node-b.out 2>&1 &
b_pid=$!

wait $a_pid
wait $b_pid
b_status=$?
if [ -n "$peer" ]; then
  for _ in $(seq 50); do kill -0 "$peer_pid" 2>/dev/null || break; sleep 0.1; done
  kill "$peer_pid" 2>/dev/null
  wait "$peer_pid" 2>/dev/null
fi
kill $cp_pid 2>/dev/null  # it lingers to keep the load balancer up
wait $cp_pid 2>/dev/null
echo "--- node a ---"
cat build/node-a.out
echo "--- node b (exit status $b_status) ---"
cat build/node-b.out
if [ -n "$peer" ]; then
  echo "--- peer ---"
  cat build/peer.log
fi
echo "--- control plane ---"
cat build/cp.log
exit "$(cat build/node-a.status 2>/dev/null || echo 2)"
