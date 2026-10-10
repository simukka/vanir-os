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

# name | app (tests/apps/<app>.toml) | user features (package/feature) | kernel features | expected status | expected text
CASES=(
  "normal          | hello               |                     |               | 1 | exited with code 0 (called from CPL 3)"
  "bad-pointer     | hello               | hello/bad-pointer   |               | 1 | bad pointers rejected"
  "poke-kernel     | hello               | hello/poke-kernel   |               | 5 | killed by vector 14"
  "exec-stack      | hello               | hello/exec-stack    |               | 5 | error=0x15"
  "write-code      | hello               | hello/write-code    |               | 5 | error=0x7"
  "smap            | hello               |                     | smap-selftest | 7 | #PF page fault in kernel mode"
  "timer-ticks     | spinner             |                     |               | 1 | re:pid 1 \(spinner\): exited 0, [1-9][0-9]* ticks"
  "preemption      | two-spinners        |                     |               | 1 | re:spinner B 0\n[\s\S]*spinner A 9\n"
  "address-spaces  | two-isolation       |                     |               | 1 | re:isolation pid 1: ok[\s\S]*isolation pid 2: ok|isolation pid 2: ok[\s\S]*isolation pid 1: ok"
  "cpu-budget      | budget              |                     |               | 5 | re:spinner\) exited with code 0[\s\S]*runaway\) killed: CPU budget of 20 ticks used up"
  "no-leak         | mixed               |                     |               | 1 | all task memory freed"
  "fault-isolated  | hello-spinner       | hello/poke-kernel   |               | 5 | re:hello\) killed by vector 14[\s\S]*spinner B 9\n[\s\S]*spinner\) exited with code 0"
  "ipc-echo        | echo-client         |                     |               | 1 | re:100 round trips ok[\s\S]*4097-byte message: TOO_LONG[\s\S]*echo\): waiting for messages"
  "ipc-queued      | two-clients         |                     |               | 1 | re:100 round trips ok[\s\S]*100 round trips ok[\s\S]*client-a\): exited 0[\s\S]*client-b\): exited 0"
  "ipc-bad-buffer  | echo-client         | client/bad-buffer   |               | 1 | re:unmapped buffer: BAD_BUFFER\n[\s\S]*echo still serving"
  "ipc-not-allowed | echo-client-spinner | client/not-allowed  |               | 1 | re:task not in .sends.: NOT_ALLOWED"
  "ipc-server-dies | echo-client         | client/crash-server |               | 5 | re:echo\) killed by vector 14[\s\S]*waited: DEAD\n[\s\S]*again: DEAD"
  "ipc-deadlock    | deadlock            |                     |               | 9 | deadlock: processes are waiting on each other"
  "supervisor-restart | supervised-crasher | | | 5 | re:restarted task 2 \(restart 3,[\s\S]*giving up on task 2 after 3 restarts[\s\S]*spinner\) exited with code 0"
  "restart-no-leak | supervised-crasher-only | supervisor/restart-3000 | | 5 | re:restarted task 2 \(restart 3000,[\s\S]*giving up on task 2 after 3000 restarts"
  "stale-id        | supervised-echo     | client/stale-id     |               | 1 | re:send to the old id: DEAD\n[\s\S]*send to the new id: ok"
  "sleep-idle      | two-sleepers        |                     |               | 1 | re:sleeper 1: woke after 1[0-3] ticks[\s\S]*sleeper 2: woke after 2[0-3] ticks[\s\S]*sleeper-a\): exited 0, [01] ticks\n[\s\S]*sleeper-b\): exited 0, [01] ticks"
  "sleep-busy      | sleep-while-busy    |                     |               | 5 | re:sleeper 2: woke after 2[0-3] ticks[\s\S]*sleeper\) exited with code 0[\s\S]*runaway\) killed: CPU budget"
)

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; echo "${s%"${s##*[![:space:]]}"}"; }

failed=0
for case in "${CASES[@]}"; do
  IFS='|' read -r name app user kernel want_status want_text <<<"$case"
  name=$(trim "$name"); app=$(trim "$app"); user=$(trim "$user"); kernel=$(trim "$kernel")
  want_status=$(trim "$want_status"); want_text=$(trim "$want_text")

  if ! build_log=$(make -s iso APP="tests/apps/$app.toml" USER_FEATURES="$user" KERNEL_FEATURES="$kernel" 2>&1); then
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