#!/usr/bin/env bash
# Run a QEMU command with a software TPM 2.0 attached (as tpm-crb).
#
#   tools/with-swtpm.sh qemu-system-x86_64 ...
#
# The TPM's state (its seeds, hence its endorsement and attestation keys) lives in build/tpm and
# persists across runs; PCRs start fresh at every boot, like a real TPM's.
set -u
state=${TPM_STATE:-build/tpm}
mkdir -p "$state"
sock="$state/swtpm.sock"
rm -f "${sock:?}"
swtpm socket --tpm2 --tpmstate dir="$state" --ctrl type=unixio,path="$sock" --log level=0 &
tpm=$!
for _ in $(seq 50); do [ -S "$sock" ] && break; sleep 0.1; done
"$@" -chardev socket,id=chrtpm,path="$sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0
status=$?
kill "$tpm" 2>/dev/null
wait "$tpm" 2>/dev/null
exit $status
