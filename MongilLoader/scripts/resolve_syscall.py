#!/usr/bin/env python3
"""
resolve_syscall.py - extract NT* syscall #s from ntoskrnl.exe via ZwXxx thunks.

Modern ntoskrnl.exe does NOT export KeServiceDescriptorTable. But it does
export ZwCreateProfile (and every other Zw thunk). Each Zw thunk has a
fixed prologue:

    4C 8B D1                mov r10, rcx
    B8 XX XX XX XX          mov eax, IMM32      <-- syscall number
    F6 04 25 08 03 FE 7F 01 test byte ptr [SharedUserData+0x308], 1
    75 03                   jne short +3
    0F 05                   syscall
    C3                      ret
    CD 2E                   int 2Eh             (legacy fallback)
    C3                      ret

We read 5 bytes at offset +3 from the export, validate the leading three
bytes are 4C 8B D1, then return the IMM32 as the syscall #.

Usage:
    python resolve_syscall.py <path-to-ntoskrnl.exe> [SymbolName...]

If no symbol names supplied, defaults to NtCreateProfile.
Outputs a C struct entry suitable for BuildInfo::kNtosBuilds.
"""
from __future__ import annotations
import sys
import hashlib
import struct
from pathlib import Path

try:
    import pefile
except ImportError:
    print("install pefile: py -m pip install pefile", file=sys.stderr)
    sys.exit(1)


def sha256_digest(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.digest()


def find_export_rva(pe: pefile.PE, name: str) -> int | None:
    target = name.encode()
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name == target:
            return exp.address
    return None


def extract_syscall_num(pe: pefile.PE, rva: int, name: str) -> int | None:
    """Read 8 bytes at the export and decode mov-r10-rcx + mov-eax-imm32."""
    data = pe.get_data(rva, 16)
    # Bytes 0..2 must be 4C 8B D1 (mov r10, rcx)
    if data[0:3] != b"\x4c\x8b\xd1":
        print(f"  WARN {name}@RVA=0x{rva:x}: prologue != mov r10,rcx; head=" +
              " ".join(f"{b:02x}" for b in data[:8]),
              file=sys.stderr)
        return None
    # Byte 3 must be B8 (mov eax, imm32)
    if data[3] != 0xB8:
        print(f"  WARN {name}@RVA=0x{rva:x}: no mov eax (got 0x{data[3]:02x})",
              file=sys.stderr)
        return None
    syscall = struct.unpack_from("<I", data, 4)[0]
    return syscall


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    path = Path(argv[1])
    if not path.is_file():
        print(f"file not found: {path}", file=sys.stderr)
        return 2

    symbols = argv[2:] if len(argv) > 2 else ["NtCreateProfile"]

    pe = pefile.PE(str(path), fast_load=False)
    pe.parse_data_directories()

    print(f"# Resolving from: {path}")
    print(f"# Image base = 0x{pe.OPTIONAL_HEADER.ImageBase:x}")

    digest = sha256_digest(path)
    s8 = digest[:8]
    s8_str = ",".join(f"0x{b:02X}" for b in s8)
    print(f"# SHA-256 = {digest.hex()}")
    print(f"# First 8 = {s8_str}")
    print()

    found: list[tuple[str, int]] = []
    for sym in symbols:
        # Try Nt* and Zw* prefixed forms.
        candidates = [sym]
        if sym.startswith("Nt"):
            candidates.append("Zw" + sym[2:])
        elif sym.startswith("Zw"):
            candidates.append("Nt" + sym[2:])

        rva = None
        used_name = None
        for c in candidates:
            rva = find_export_rva(pe, c)
            if rva is not None:
                used_name = c
                break
        if rva is None:
            print(f"# {sym}: not exported (tried {candidates})")
            continue

        syscall = extract_syscall_num(pe, rva, used_name)
        if syscall is None:
            print(f"# {sym}: prologue mismatch (export {used_name}@RVA=0x{rva:x})")
            continue

        print(f"#   {used_name:30s} RVA=0x{rva:08x}  syscall=0x{syscall:04X} ({syscall})")
        found.append((sym, syscall))

    if not found:
        return 1

    primary_name, primary_num = found[0]
    label = f"Win10 {pe.FILE_HEADER.TimeDateStamp:08X} {primary_name}"
    print()
    print("// Append to BuildInfo::kNtosBuilds:")
    print(f"{{ {{{s8_str}}}, 0x{primary_num:04X}, \"{label}\" }},")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
