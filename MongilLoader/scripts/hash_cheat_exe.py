#!/usr/bin/env python3
"""
hash_cheat_exe.py - emit SHA-256 of cheat exe .text section into BuildInfo.h.

The MongilLoader VMM uses kExpectedCheatExeHash to authenticate the OPHION_OP_REGISTER
caller. Run this AFTER cheat exe is built to embed its hash into BuildInfo.h
before rebuilding MongilLoader.

Usage:
    py hash_cheat_exe.py <path-to-cheat.exe> [--update-buildinfo PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    print("install pefile: py -m pip install pefile", file=sys.stderr)
    sys.exit(1)


def hash_text_section(exe_path: Path) -> bytes:
    pe = pefile.PE(str(exe_path), fast_load=False)
    pe.parse_data_directories()
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        if name == ".text":
            data = pe.get_data(sec.VirtualAddress, sec.SizeOfRawData)
            return hashlib.sha256(data).digest()
    raise RuntimeError(".text section not found")


def fmt_c_array(b: bytes) -> str:
    return ", ".join(f"0x{x:02X}" for x in b)


def update_buildinfo(buildinfo_path: Path, hash_bytes: bytes) -> bool:
    text = buildinfo_path.read_text(encoding="utf-8")

    # Find the kExpectedCheatExeHash array initializer and replace its body.
    pat = re.compile(
        r"(static const uint8_t kExpectedCheatExeHash\[32\]\s*=\s*\{)([^}]+)(\};)",
        re.DOTALL,
    )
    if not pat.search(text):
        print(f"WARNING: kExpectedCheatExeHash not found in {buildinfo_path}",
              file=sys.stderr)
        return False

    new_body = "\n    " + ", ".join(
        ", ".join(f"0x{x:02X}" for x in hash_bytes[i : i + 8])
        for i in range(0, 32, 8)
    ) + "\n"
    new_text = pat.sub(rf"\1{new_body}\3", text)
    buildinfo_path.write_text(new_text, encoding="utf-8")
    print(f"updated: {buildinfo_path}")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("exe", type=Path)
    ap.add_argument("--update-buildinfo", type=Path, default=None,
                    help="path to BuildInfo.h; updates kExpectedCheatExeHash")
    args = ap.parse_args()

    if not args.exe.is_file():
        print(f"file not found: {args.exe}", file=sys.stderr)
        return 2

    h = hash_text_section(args.exe)
    print(f"# {args.exe.name} .text SHA-256")
    print(f"#   hex: {h.hex()}")
    print(f"#   array: {fmt_c_array(h)}")

    if args.update_buildinfo:
        if not args.update_buildinfo.is_file():
            print(f"--update-buildinfo: file not found: {args.update_buildinfo}",
                  file=sys.stderr)
            return 2
        if not update_buildinfo(args.update_buildinfo, h):
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
