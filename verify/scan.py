#!/usr/bin/env python3
"""YARA-X scanner for verifying obfuscation effectiveness.

Usage:
    # Compare original vs obfuscated:
    python verify/scan.py cache/assemblies/sharpkatz/SharpKatz.exe /tmp/obfuscated.exe

    # Scan a single file:
    python verify/scan.py /tmp/obfuscated.exe

    # Use custom rules:
    python verify/scan.py --rules /path/to/rules.yar file.exe
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

import yara_x

DEFAULT_RULES = Path(__file__).parent / "rules" / "packages" / "full" / "yara-rules-full.yar"

# Severity mapping: rule name prefixes → risk level
_SEVERITY = {
    "HKTL": "HIGH",       # Hack tool signature
    "MALWARE": "HIGH",    # Known malware
    "INDICATOR_TOOL": "HIGH",
    "CAPE": "MEDIUM",     # CAPE sandbox rule (e.g. packer/obfuscator ID)
    "SIGNATURE_BASE": "MEDIUM",
    "DITEKSHEN": "MEDIUM",
    "ELASTIC": "HIGH",
}


def _severity(rule_name: str) -> str:
    for prefix, level in _SEVERITY.items():
        if prefix in rule_name.upper():
            return level
    return "LOW"


def _compile_rules(rules_path: Path) -> yara_x.Rules:
    src = rules_path.read_text()
    compiler = yara_x.Compiler()
    compiler.add_source(src)
    return compiler.build()


def _scan(rules: yara_x.Rules, data: bytes) -> list[dict]:
    results = rules.scan(data)
    matches = []
    for m in results.matching_rules:
        matches.append({
            "rule": m.identifier,
            "namespace": m.namespace,
            "severity": _severity(m.identifier),
        })
    return sorted(matches, key=lambda x: ("HIGH", "MEDIUM", "LOW").index(x["severity"]))


def _file_info(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "data": data,
    }


def _print_results(label: str, info: dict, matches: list[dict]) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {label}")
    print(f"{'=' * 60}")
    print(f"  File:   {info['path']}")
    print(f"  Size:   {info['size']:,} bytes")
    print(f"  SHA256: {info['sha256']}")
    print()

    if not matches:
        print("  \033[92mNO DETECTIONS\033[0m")
    else:
        print(f"  \033[91m{len(matches)} DETECTION(S)\033[0m")
        print()
        for m in matches:
            color = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[90m"}[m["severity"]]
            reset = "\033[0m"
            print(f"    {color}[{m['severity']:6s}]{reset}  {m['rule']}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan PE files against YARA Forge rules")
    parser.add_argument("files", nargs="+", help="PE files to scan (first = baseline if >1)")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="YARA rules file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if not args.rules.exists():
        print(f"Rules file not found: {args.rules}", file=sys.stderr)
        print("Run: wget the YARA Forge rules into verify/rules/", file=sys.stderr)
        return 1

    print(f"Compiling rules from {args.rules.name}...", end=" ", flush=True)
    t0 = time.time()
    rules = _compile_rules(args.rules)
    print(f"done ({time.time() - t0:.1f}s)")

    files = [Path(f) for f in args.files]
    all_results = []

    for i, fp in enumerate(files):
        if not fp.exists():
            print(f"File not found: {fp}", file=sys.stderr)
            return 1

        info = _file_info(fp)
        t0 = time.time()
        matches = _scan(rules, info["data"])
        scan_time = time.time() - t0

        label = "ORIGINAL (baseline)" if i == 0 and len(files) > 1 else f"SAMPLE {i + 1}" if len(files) > 1 else fp.name
        _print_results(label, info, matches)
        print(f"  Scan time: {scan_time:.2f}s")

        all_results.append({"file": str(fp), "matches": matches})

    # Comparison summary when scanning multiple files
    if len(files) > 1:
        baseline_rules = {m["rule"] for m in all_results[0]["matches"]}
        print(f"\n{'=' * 60}")
        print("  COMPARISON SUMMARY")
        print(f"{'=' * 60}")
        for i, result in enumerate(all_results[1:], 1):
            sample_rules = {m["rule"] for m in result["matches"]}
            removed = baseline_rules - sample_rules
            added = sample_rules - baseline_rules
            kept = baseline_rules & sample_rules

            print(f"\n  Sample {i + 1} vs baseline:")
            if removed:
                print(f"    \033[92mRemoved ({len(removed)}):\033[0m")
                for r in sorted(removed):
                    print(f"      - {r}")
            if kept:
                print(f"    \033[93mStill detected ({len(kept)}):\033[0m")
                for r in sorted(kept):
                    print(f"      ! {r}")
            if added:
                print(f"    \033[91mNew detections ({len(added)}):\033[0m")
                for r in sorted(added):
                    print(f"      + {r}")
            if not removed and not added and not kept:
                print("    Both clean")

            # Score
            baseline_count = len(baseline_rules)
            if baseline_count > 0:
                evasion_pct = len(removed) / baseline_count * 100
                print(f"\n    Evasion rate: {evasion_pct:.0f}% of baseline signatures removed")
            if not sample_rules:
                print("    \033[92mFULLY CLEAN — no detections\033[0m")
        print()

    # Return non-zero if the last file has detections
    return 1 if all_results[-1]["matches"] else 0


if __name__ == "__main__":
    sys.exit(main())
