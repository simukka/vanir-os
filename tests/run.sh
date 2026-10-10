#!/usr/bin/env bash
# Boot each scenario in QEMU and check its exit status and serial output.
#
# QEMU exit status is (code << 1) | 1 via isa-debug-exit:
#   1 = every process exited 0, 3 = some process exited non-zero, 5 = some process was killed,
#   7 = kernel fault or panic.
#
# Expected text is a fixed string; with an "re:" prefix, a Perl regex matched against the whole
# output (so [\s\S]* can span lines and check ordering); with "cmd:", a shell command that gets
# the output on stdin and must succeed.
set -u
cd "$(dirname "$0")/.."

# name | app (tests/apps/<app>.toml) | user features (package/feature) | kernel features |
#   make variables (e.g. TRANSPORT=vsock ACCEL=kvm) | expected status | expected text
CASES=(
  "normal               | hello                   |                                                           |               |                                                                          | 1 | exited with code 0 (called from CPL 3)"
  "bad-pointer          | hello                   | hello/bad-pointer                                         |               |                                                                          | 1 | bad pointers rejected"
  "poke-kernel          | hello                   | hello/poke-kernel                                         |               |                                                                          | 5 | killed by vector 14"
  "exec-stack           | hello                   | hello/exec-stack                                          |               |                                                                          | 5 | error=0x15"
  "write-code           | hello                   | hello/write-code                                          |               |                                                                          | 5 | error=0x7"
  "smap                 | hello                   |                                                           | smap-selftest |                                                                          | 7 | #PF page fault in kernel mode"
  "timer-ticks          | spinner                 |                                                           |               |                                                                          | 1 | re:pid 1 \(spinner\): exited 0, [1-9][0-9]* ticks"
  "preemption           | two-spinners            |                                                           |               |                                                                          | 1 | re:spinner B 0\n[\s\S]*spinner A 9\n"
  "address-spaces       | two-isolation           |                                                           |               |                                                                          | 1 | re:isolation pid 1: ok[\s\S]*isolation pid 2: ok|isolation pid 2: ok[\s\S]*isolation pid 1: ok"
  "cpu-budget           | budget                  |                                                           |               |                                                                          | 5 | re:spinner\) exited with code 0[\s\S]*runaway\) killed: CPU budget of 20 ticks used up"
  "no-leak              | mixed                   |                                                           |               |                                                                          | 1 | all task memory freed"
  "fault-isolated       | hello-spinner           | hello/poke-kernel                                         |               |                                                                          | 5 | re:hello\) killed by vector 14[\s\S]*spinner B 9\n[\s\S]*spinner\) exited with code 0"
  "ipc-echo             | echo-client             |                                                           |               |                                                                          | 1 | re:100 round trips ok[\s\S]*4097-byte message: TOO_LONG[\s\S]*echo\): waiting for messages"
  "ipc-queued           | two-clients             |                                                           |               |                                                                          | 1 | re:100 round trips ok[\s\S]*100 round trips ok[\s\S]*client-a\): exited 0[\s\S]*client-b\): exited 0"
  "ipc-bad-buffer       | echo-client             | client/bad-buffer                                         |               |                                                                          | 1 | re:unmapped buffer: BAD_BUFFER\n[\s\S]*echo still serving"
  "ipc-not-allowed      | echo-client-spinner     | client/not-allowed                                        |               |                                                                          | 1 | re:task not in .sends.: NOT_ALLOWED"
  "ipc-server-dies      | echo-client             | client/crash-server                                       |               |                                                                          | 5 | re:echo\) killed by vector 14[\s\S]*waited: DEAD\n[\s\S]*again: DEAD"
  "ipc-deadlock         | deadlock                |                                                           |               |                                                                          | 9 | deadlock: processes are waiting on each other"
  "supervisor-restart   | supervised-crasher      |                                                           |               |                                                                          | 5 | re:(?=[\s\S]*spinner\) exited with code 0)[\s\S]*restarted task 2 \(restart 3,[\s\S]*giving up on task 2 after 3 restarts"
  "restart-no-leak      | supervised-crasher-only | supervisor/restart-3000                                   |               |                                                                          | 5 | re:restarted task 2 \(restart 3000,[\s\S]*giving up on task 2 after 3000 restarts"
  "stale-id             | supervised-echo         | client/stale-id                                           |               |                                                                          | 1 | re:send to the old id: DEAD\n[\s\S]*send to the new id: ok"
  "sleep-idle           | two-sleepers            |                                                           |               |                                                                          | 1 | re:sleeper 1: woke after 1[0-3] ticks[\s\S]*sleeper 2: woke after 2[0-3] ticks[\s\S]*sleeper-a\): exited 0, [01] ticks\n[\s\S]*sleeper-b\): exited 0, [01] ticks"
  "sleep-busy           | sleep-while-busy        |                                                           |               |                                                                          | 5 | re:sleeper 2: woke after 2[0-3] ticks[\s\S]*sleeper\) exited with code 0[\s\S]*runaway\) killed: CPU budget"
  "device-grant         | devprobe                |                                                           |               |                                                                          | 1 | re:pci 00:0[0-9a-f]\.0 1af4:1043 virtio-console[\s\S]*devprobe: device 1af4:1043[\s\S]*virtio common config in BAR 4 .*num_queues [0-9]+"
  "device-no-grant      | devprobe-no-grant       |                                                           |               |                                                                          | 1 | devprobe: no device granted: BAD_ARGUMENT"
  "device-msix          | devprobe                | devprobe/poke-msix                                        |               |                                                                          | 5 | re:BAR 1 \(MSI-X\) visible to us: false[\s\S]*devprobe\) killed by vector 14"
  "dma-region           | dma                     |                                                           |               |                                                                          | 1 | re:(?=[\s\S]*restarted task 2 )[\s\S]*start 0: 16 KiB at 0x2000000000, physical (0x[0-9a-f]+), all zero: true[\s\S]*start 1: 16 KiB at 0x2000000000, physical \1, all zero: true[\s\S]*region ok after restart"
  "dma-none             | dma-none                |                                                           |               |                                                                          | 1 | dmatest: no DMA region: BAD_ARGUMENT"
  "console-write        | console                 |                                                           |               |                                                                          | 1 | cmd:tools/check_lines.py 'line ' 200 | grep -q '(0 resent)'"
  "console-restart      | console-restart         | virtio-console/crash-after-50                             |               |                                                                          | 1 | cmd:out=\$(cat); tools/check_lines.py 'line ' 200 <<<\"\$out\" && grep -q 'driver restarted 1 times' <<<\"\$out\""
  "telemetry            | telemetry               | telemetry/exit-after-3-heartbeats                         |               |                                                                          | 5 | cmd:out=\$(cat); tools/host-agent.py - --check --quiet --expect-heartbeats 3 --expect fault=4 --expect restart=3 --expect log=1 <<<\"\$out\" && grep -q '\"msg\":\"giving up on task 2 after 3 restarts\"' <<<\"\$out\""
  "telemetry-flood      | telemetry-flood         | telemetry/exit-after-3-heartbeats supervisor/restart-3000 |               |                                                                          | 5 | cmd:tools/host-agent.py - --check --quiet --expect-heartbeats 3 --expect dropped=1"
  "telemetry-vsock      | telemetry-vsock         | telemetry/exit-after-3-heartbeats                         |               | TRANSPORT=vsock ACCEL=kvm                                                | 5 | cmd:out=\$(cat); tools/host-agent.py - --check --quiet --expect-heartbeats 3 --expect fault=4 --expect restart=3 <<<\"\$out\" && grep -q 'virtio-vsock: connected to host port 5000' <<<\"\$out\""
  "sig-tamper           | sig-pair                |                                                           |               | TAMPER=hello                                                             | 5 | re:pid 1 \(hello\): image REJECTED: image does not match its signature[\s\S]*spinner\) exited with code 0"
  "sig-unsigned         | sig-pair                |                                                           |               | UNSIGNED=hello                                                           | 5 | re:pid 1 \(hello\): image REJECTED: no signature[\s\S]*spinner\) exited with code 0"
  "sig-swapped          | sig-pair                |                                                           |               | SWAP_SIGS=hello:spinner                                                  | 5 | re:hello\): image REJECTED: signed for another program[\s\S]*spinner\): image REJECTED: signed for another program[\s\S]*no process can run"
  "sig-rogue-key        | sig-pair                |                                                           |               | SIGNING_KEY=build/rogue.key TRUSTED_PUB=keys/dev-signing.pub             | 5 | re:hello\): image REJECTED: signature does not verify[\s\S]*spinner\): image REJECTED: signature does not verify"
  "sig-rollback         | sig-rollback            |                                                           |               |                                                                          | 5 | re:pid 1 \(hello\): image REJECTED: version older than the manifest allows[\s\S]*spinner\) exited with code 0"
  "sig-supervised       | sig-supervised          |                                                           |               | TAMPER=hello                                                             | 5 | re:task 2 image rejected \(image does not match its signature\): not starting it[\s\S]*spinner\) exited with code 0"
  "sb-boot              | hello                   |                                                           |               | BOOT=uefi-secure ACCEL=kvm                                               | 1 | re:limine: Loading executable .boot\(\):/boot/vanir-kernel.[\s\S]*signed version 1[\s\S]*hello\) exited with code 0"
  "sb-tampered-kernel   | hello                   |                                                           |               | BOOT=uefi-secure ACCEL=kvm SB_TAMPER_KERNEL=1 TIMEOUT=25                 | 124 | re:Blake2b hash for URI .boot\(\):/boot/vanir-kernel. does not match"
  "sb-edited-config     | hello                   |                                                           |               | BOOT=uefi-secure ACCEL=kvm SB_EDIT_CONFIG=1 TIMEOUT=25                   | 124 | CHECKSUM MISMATCH FOR CONFIG FILE"
  "sb-unsigned-loader   | hello                   |                                                           |               | BOOT=uefi-secure ACCEL=kvm SB_UNSIGNED_LOADER=1 TIMEOUT=25               | 124 | re:failed to load Boot[0-9]+ .UEFI QEMU HARDDISK[^\n]*Access Denied"
  "measured-boot        | sig-pair                |                                                           |               | BOOT=uefi-secure ACCEL=kvm TPM=1                                         | 1 | cmd:out=\$(cat); want=\$(tools/expected-pcrs.py --app tests/apps/sig-pair.toml); grep -q \"tpm: PCR12 = \$want\" <<<\"\$out\""
  "measured-rejected    | sig-pair                |                                                           |               | BOOT=uefi-secure ACCEL=kvm TPM=1 TAMPER=hello                            | 5 | cmd:out=\$(cat); want=\$(tools/expected-pcrs.py --app tests/apps/sig-pair.toml --rejected hello); grep -q \"tpm: PCR12 = \$want\" <<<\"\$out\""
  "no-tpm               | hello                   |                                                           |               |                                                                          | 1 | tpm: none found; the boot is not measured"
  "attest-record        | attest                  | control/one-shot                                          |               | BOOT=uefi-secure ACCEL=kvm TPM=1 TRANSPORT=vsock ATTEST=1                | 1 | cmd:tools/verify-quote.py --log build/telemetry.log --record build/attest-reference.json --expected-pcr12 \$(tools/expected-pcrs.py --app tests/apps/attest.toml)"
  "attest-verify        | attest                  | control/one-shot                                          |               | BOOT=uefi-secure ACCEL=kvm TPM=1 TRANSPORT=vsock ATTEST=1                | 1 | cmd:tools/verify-quote.py --log build/telemetry.log --reference build/attest-reference.json"
  "attest-replay        | attest                  | control/one-shot                                          |               | BOOT=uefi-secure ACCEL=kvm TPM=1 TRANSPORT=vsock ATTEST=1                | 1 | cmd:tools/verify-quote.py --log build/telemetry.log --reference build/attest-reference.json --nonce 00 | grep -q 'FAIL: the quote is not over this challenge'"
  "attest-tampered      | attest                  | control/one-shot                                          |               | BOOT=uefi-secure ACCEL=kvm TPM=1 TRANSPORT=vsock ATTEST=1                | 1 | cmd:tools/verify-quote.py --log build/telemetry.log --reference build/attest-reference.json --tamper | grep -q 'FAIL: the signature does not verify'"
  "attest-other-version | attest                  | control/one-shot                                          |               | BOOT=uefi-secure ACCEL=kvm TPM=1 TRANSPORT=vsock ATTEST=1 SIGN_VERSION=2 | 1 | cmd:tools/verify-quote.py --log build/telemetry.log --reference build/attest-reference.json | grep -q 'FAIL: PCR 12 (kernel/manifest/tasks) differs'"
  "blk-rw               | blk                     |                                                           |               | DISK=1 DISK_RESET=1                                                      | 1 | re:wrote 32 blocks[\s\S]*read back 32 blocks, all correct[\s\S]*past the end\) refused"
  "blk-persist          | blk                     | blktest/check-only                                        |               | DISK=1                                                                   | 1 | read back 32 blocks, all correct"
  "blk-persist-negative | blk                     | blktest/check-only                                        |               | DISK=1 DISK_RESET=1                                                      | 3 | block 0 has the wrong contents"
  "blk-restart          | blk-supervised          | virtio-blk/crash-after-10                                 |               | DISK=1 DISK_RESET=1                                                      | 1 | re:crashing with a write in flight[\s\S]*read back 32 blocks, all correct"
  "storage-isolation    | storage                 |                                                           |               | DISK=1 DISK_RESET=1                                                      | 1 | re:(?=[\s\S]*client-a read back 32 blocks, all correct)(?=[\s\S]*client-b read back 32 blocks, all correct)[\s\S]*new volume for client-a[\s\S]*new volume for client-b"
  "storage-persist      | storage                 | blktest/check-only                                        |               | DISK=1                                                                   | 1 | re:(?=[\s\S]*client-a read back 32 blocks, all correct)(?=[\s\S]*client-b read back 32 blocks, all correct)[\s\S]*2 volume\(s\) on the disk"
  "storage-no-driver    | storage-poke            | blktest/poke-driver                                       |               | DISK=1                                                                   | 1 | talking to the block driver directly: NOT_ALLOWED"
)

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; echo "${s%"${s##*[![:space:]]}"}"; }

failed=0
for case in "${CASES[@]}"; do
  IFS='|' read -r name app user kernel env want_status want_text <<<"$case"
  name=$(trim "$name"); app=$(trim "$app"); env=$(trim "$env"); user=$(trim "$user"); kernel=$(trim "$kernel")
  want_status=$(trim "$want_status"); want_text=$(trim "$want_text")

  vars=(ACCEL="${ACCEL:-tcg}" $env)
  limit=60
  for v in $env; do [[ "$v" == TIMEOUT=* ]] && limit=${v#TIMEOUT=}; done
  wrap=()
  if [[ " $env " == *" TRANSPORT=vsock "* ]]; then
    # vhost-vsock needs /dev/vhost-vsock (the kvm group): use `sg kvm` if this login predates it.
    if [ -w /dev/vhost-vsock ]; then wrap=(bash -c)
    elif sg kvm -c 'test -w /dev/vhost-vsock' 2>/dev/null; then wrap=(sg kvm -c)
    else echo "SKIP $name: no access to /dev/vhost-vsock (join the kvm group)"; continue
    fi
  fi
  if ! build_log=$(make -s image APP="tests/apps/$app.toml" USER_FEATURES="$user" KERNEL_FEATURES="$kernel" "${vars[@]}" 2>&1); then
    echo "FAIL $name: build failed"; echo "$build_log"; failed=1; continue
  fi
  qemu=$(make -s qemu-cmd "${vars[@]}")
  if [ ${#wrap[@]} -ne 0 ]; then
    rm -f build/telemetry.log
    agent_args=()
    [[ " $env " == *" ATTEST=1 "* ]] && agent_args+=(--attest)
    tools/host-agent.py --listen-vsock 5000 --save build/telemetry.log --quiet "${agent_args[@]}" >/dev/null 2>&1 &
    agent=$!
    for _ in $(seq 50); do [ -e build/telemetry.log ] && break; sleep 0.1; done
    out=$(timeout "$limit" "${wrap[@]}" "$qemu" 2>&1)
    status=$?
    sleep 0.5; kill $agent 2>/dev/null; wait $agent 2>/dev/null
  else
    out=$(timeout "$limit" $qemu 2>&1)
    status=$?
  fi
  # Firmware consoles (OVMF under BOOT=uefi-secure) position every character with escape codes;
  # match against plain text.
  out=$(sed 's/\x1b\[[0-9;:?=]*[A-Za-z]//g; s/\x1b[()][0-9A-Za-z]//g; s/\r//g' <<<"$out")
  # What reached the host over the virtio console, for the checks below.
  out+=$'\n--- build/telemetry.log ---\n'"$(cat build/telemetry.log 2>/dev/null)"

  if [[ "$want_text" == re:* ]]; then
    grep -Pzq -- "${want_text#re:}" <<<"$out"; text_ok=$?
  elif [[ "$want_text" == cmd:* ]]; then
    check_out=$(bash -c "${want_text#cmd:}" <<<"$out" 2>&1); text_ok=$?
    [ "$text_ok" -eq 0 ] || echo "    check: $check_out"
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