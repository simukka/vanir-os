#!/usr/bin/env bash
# Boot each scenario in QEMU and check its exit status and serial output.
#
# QEMU exit status is (code << 1) | 1 via isa-debug-exit:
#   1 = process exit(0), 3 = process exit(non-zero), 5 = process killed by a fault,
#   7 = kernel fault or panic.
set -u
cd "$(dirname "$0")/.."

# name | user features | kernel features | expected status | expected serial text
CASES=(
  "normal       |              |               | 1 | process exited with code 0 (called from CPL 3)"
  "poke-kernel  | poke-kernel  |               | 5 | cr2=0xffffffff80000000"
  "smap         |              | smap-selftest | 7 | #PF page fault in kernel mode"
)

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; echo "${s%"${s##*[![:space:]]}"}"; }

failed=0
for case in "${CASES[@]}"; do
  IFS='|' read -r name user kernel want_status want_text <<<"$case"
  name=$(trim "$name"); user=$(trim "$user"); kernel=$(trim "$kernel")
  want_status=$(trim "$want_status"); want_text=$(trim "$want_text")

  if ! build_log=$(make -s iso USER_FEATURES="$user" KERNEL_FEATURES="$kernel" 2>&1); then
    echo "FAIL $name: build failed"; echo "$build_log"; failed=1; continue
  fi
  out=$(timeout 30 $(make -s qemu-cmd) 2>&1)
  status=$?

  if [ "$status" -eq "$want_status" ] && grep -qF -- "$want_text" <<<"$out"; then
    echo "PASS $name (status $status)"
  else
    echo "FAIL $name: status $status (want $want_status), want text: $want_text"
    sed 's/^/    /' <<<"$out"
    failed=1
  fi
done
exit $failed
