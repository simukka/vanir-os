#!/usr/bin/env python3
"""Verify a vanir-os TPM quote from the telemetry log against an approved reference.

  verify-quote.py --log build/telemetry.log --record REF --expected-pcr12 HEX
      Check a known-good boot's quote and save it as the reference: the attestation key (trusted
      on first use), PCRs 0, 4, 7 (firmware, boot loader, Secure Boot state) as observed, and
      PCR 12 as computed from the approved build (tools/expected-pcrs.py).

  verify-quote.py --log build/telemetry.log --reference REF
      Check a later boot's quote: signed by the reference key, over the nonce the host sent,
      with exactly the reference PCR values.

Checks: TPMS_ATTEST is TPM-generated and a quote; its extraData is the challenge nonce; the
ECDSA P-256 signature verifies; its PCR digest matches the reported PCR values; the kernel's
measurement log replays to the reported PCR 12.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vanir_attest import check, compare  # noqa: E402


def last(records, event):
    found = [r for r in records if r.get("event") == event]
    if not found:
        sys.exit(f"verify-quote: FAIL: no {event} record in the log")
    return found[-1]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", default="build/telemetry.log")
    p.add_argument("--record", metavar="REF")
    p.add_argument("--expected-pcr12")
    p.add_argument("--reference", metavar="REF")
    p.add_argument("--nonce", help="check against this nonce instead of the logged challenge")
    p.add_argument("--tamper", action="store_true", help="flip a bit of the quote first (tests)")
    args = p.parse_args()
    if bool(args.record) == bool(args.reference):
        sys.exit("give --record or --reference")

    records = []
    for line in open(args.log, encoding="utf-8", errors="replace"):
        try:
            records.append(json.loads(line))
        except ValueError:
            pass
    quote = last(records, "quote")
    nonce = args.nonce or last(records, "challenge")["nonce"]
    problems = check(quote, nonce, args.tamper)

    if args.record:
        if not args.expected_pcr12:
            sys.exit("--record needs --expected-pcr12 (tools/expected-pcrs.py)")
        if quote["pcrs"]["12"] != args.expected_pcr12:
            problems.append("PCR 12 is not what the approved build measures to")
        if not problems:
            reference = {"ak_x": quote["ak_x"], "ak_y": quote["ak_y"],
                         "pcrs": {p: quote["pcrs"][p] for p in ["0", "4", "7"]} | {"12": args.expected_pcr12}}
            with open(args.record, "w") as f:
                json.dump(reference, f, indent=2)
    else:
        problems += compare(quote, json.load(open(args.reference)))

    for problem in problems:
        print(f"verify-quote: FAIL: {problem}")
    if problems:
        sys.exit(1)
    print(f"verify-quote: OK ({'recorded' if args.record else 'matches'} reference; nonce {nonce[:16]}..., "
          f"PCR12 {quote['pcrs']['12'][:16]}...)")


if __name__ == "__main__":
    main()
