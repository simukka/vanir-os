#!/usr/bin/env bash
# Boot each scenario in QEMU and check its exit status and serial output.
#
# QEMU exit status is (code << 1) | 1 via isa-debug-exit:
#   1 = every process exited 0, 3 = some process exited non-zero, 5 = some process was killed,
#   7 = kernel fault or panic.
#
# Expected text is a fixed string, or with an "re:" prefix a Perl regex matched against the
# whole output (so [\s\S]* can span lines and check ordering).
set -u
cd "$(dirname "$0")/.."

# name | tasks | user (hello) features | kernel features | expected status | expected text
CASES=(
  "normal         | hello         |              |               | 1 | exited with code 0 (called from CPL 3)"
  "bad-pointer    | hello         | bad-pointer  |               | 1 | bad pointers rejected"
  "poke-kernel    | hello         | poke-kernel  |               | 5 | killed by vector 14"
  "exec-stack     | hello         | exec-stack   |               | 5 | error=0x15"
  "write-code     | hello         | write-code   |               | 5 | error=0x7"
  "smap           | hello         |              | smap-selftest | 7 | #PF page fault in kernel mode"
  "timer-ticks    | spinner       |              |               | 1 | re:pid 1 \(spinner\): exited 0, [1-9][0-9]* ticks"
  "preemption     | spinner spinner |            |               | 1 | re:spinner B 0\n[\s\S]*spinner A 9\n"
  "address-spaces | isolation isolation |        |               | 1 | re:isolation pid 1: ok[\s\S]*isolation pid 2: ok|isolation pid 2: ok[\s\S]*isolation pid 1: ok"
  "cpu-budget     | runaway:20 spinner |         |               | 5 | re:spinner\) exited with code 0[\s\S]*runaway\) killed: CPU budget of 20 ticks used up"
  "fault-isolated | hello spinner | poke-kernel  |               | 5 | re:hello\) killed by vector 14[\s\S]*spinner B 9\n[\s\S]*spinner\) exited with code 0"
)

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; echo "${s%"${s##*[![:space:]]}"}"; }

failed=0
for case in "${CASES[@]}"; do
  IFS='|' read -r name tasks user kernel want_status want_text <<<"$case"
  name=$(trim "$name"); tasks=$(trim "$tasks"); user=$(trim "$user"); kernel=$(trim "$kernel")
  want_status=$(trim "$want_status"); want_text=$(trim "$want_text")

  if ! build_log=$(make -s iso TASKS="$tasks" USER_FEATURES="$user" KERNEL_FEATURES="$kernel" 2>&1); then
    echo "FAIL $name: build failed"; echo "$build_log"; failed=1; continue
  fi
  out=$(timeout 60 $(make -s qemu-cmd ACCEL="${ACCEL:-tcg}") 2>&1)
  status=$?

  if [[ "$want_text" == re:* ]]; then
    grep -Pzq -- "${want_text#re:}" <<<"$out"; text_ok=$?
  else
    grep -qF -- "$want_text" <<<"$out"; text_ok=$?
  fi

  if [ "$status" -eq "$want_status" ] && [ "$text_ok" -eq 0 ]; then
    echo "PASS $name (status $status)"
  else
    echo "FAIL $name: status $status (want $want_status), want text: $want_text"
    sed 's/^/    /' <<<"$out"
    failed=1
  fi
done
exit $failed
