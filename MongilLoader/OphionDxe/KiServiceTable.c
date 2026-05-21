/*
 * KiServiceTable.c - locate ntoskrnl + NtCreateProfile via signature scan
 *
 * Modern Win10 19045 ntoskrnl.exe does NOT export KeServiceDescriptorTable.
 * Two-step strategy:
 *
 * Step 1: locate ntoskrnl image in memory.
 *   When MongilLoader's ExitBootServices callback fires, winload has loaded
 *   ntoskrnl and bootmgfw is about to hand off. Walk EFI_LOADED_IMAGE_PROTOCOL
 *   handles via gBS->LocateHandle(ByProtocol, gEfiLoadedImageProtocolGuid).
 *   Filter for the image whose FilePath matches "ntoskrnl.exe".
 *
 *   Alternative: VMM-side resolution. Once VMLAUNCH'd, trap the first guest
 *   syscall, read MSR_LSTAR (KiSystemCall64), walk back to ntos image base
 *   (PE header at first page-aligned address with MZ + valid PE).
 *
 * Step 2: locate NtCreateProfile body.
 *   - parse ntos PE export table for NtCreateProfile (often NOT exported by
 *     name but Zw counterpart is — Zw thunks aren't useful here because they
 *     just issue the syscall).
 *   - signature scan ntos.text for the syscall # opcode pattern using the
 *     dispatcher itself: KiSystemCall64 reads KiServiceTable[rax]. Find
 *     KiServiceTable via the LEA in KiSystemCall64 prologue.
 *
 *   Robust pattern (Win10 19045 ntoskrnl.exe):
 *     KiSystemCall64SwapGs:
 *       0F 01 F8                     swapgs
 *       65 48 89 24 25 10 00 00 00   mov gs:[10h], rsp
 *       65 48 8B 24 25 a8 01 00 00   mov rsp, gs:[1A8h]
 *       ...
 *       4C 8D 15 ?? ?? ?? ??         lea r10, [KiServiceTable]
 *       4C 8D 1D ?? ?? ?? ??         lea r11, [KiArgumentTable]
 *
 *   The 4C 8D 15 sig + RIP-relative dword = KiServiceTable VA.
 *   Then KiServiceTable[syscall_num] = (rva << 4) | argbytes
 *   NtCreateProfile_va = KiServiceTable + (entry_dword >> 4) (sign-extended)
 *
 * Phase 4 placeholder: full impl runs in VMM context post-VMLAUNCH. This
 * file currently provides the pattern constants + a pure-C helper that takes
 * an ntos image base + size and resolves the function address.
 */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>

#include "EfiCompat.h"

// Sig: 4C 8D 15 ?? ?? ?? ?? 4C 8D 1D ?? ?? ?? ?? F7 43 70
// (LEA r10,[KiServiceTable] + LEA r11,[KiArgumentTable] + test on KTHREAD)
static CONST UINT8 kServiceTableSig[] = {
    0x4C, 0x8D, 0x15        // mov r10, [rip+disp32]   (3 bytes)
};
#define K_SERVICE_TABLE_SIG_LEN  3

// Search up to 0x4000 bytes after the LEA r10 to confirm we landed on
// KiSystemCall64 vs another LEA pattern.
#define K_SERVICE_TABLE_CONFIRM_OFFSET  7   // bytes 7..9 should be 4C 8D 1D (LEA r11)

/*
 * Walk image bytes for the LEA r10/r11 pair that fronts KiServiceTable.
 * Returns the VA of KiServiceTable on hit, 0 on miss.
 */
UINT64
KiResolveServiceTable(
    IN UINT8 *ntos_base,
    IN UINTN  ntos_size
    )
{
    if (ntos_size < 0x10000) return 0;

    // Cap scan at 8MB (typical ntoskrnl < 12MB; we want .text region only).
    UINTN scan_end = ntos_size > (8 * 1024 * 1024) ? (8 * 1024 * 1024) : ntos_size;

    for (UINTN off = 0; off + 0x20 < scan_end; ++off) {
        if (ntos_base[off + 0] != kServiceTableSig[0]) continue;
        if (ntos_base[off + 1] != kServiceTableSig[1]) continue;
        if (ntos_base[off + 2] != kServiceTableSig[2]) continue;

        // Confirm via LEA r11 at off+7
        if (ntos_base[off + K_SERVICE_TABLE_CONFIRM_OFFSET + 0] != 0x4C) continue;
        if (ntos_base[off + K_SERVICE_TABLE_CONFIRM_OFFSET + 1] != 0x8D) continue;
        if (ntos_base[off + K_SERVICE_TABLE_CONFIRM_OFFSET + 2] != 0x1D) continue;

        // RIP-relative disp32 at off+3..off+6
        INT32 disp = *(INT32 *)&ntos_base[off + 3];
        UINT64 lea_next_rip = (UINT64)(UINTN)&ntos_base[off + 7];
        UINT64 service_table_va = lea_next_rip + (INT64)disp;

        Print(L"[KiResolve] candidate @ off=0x%lx -> KiServiceTable @ 0x%llx\n",
              (UINT64)off, service_table_va);
        return service_table_va;
    }
    return 0;
}

/*
 * Decode KiServiceTable entry into NtXxx body VA.
 *
 * Each entry is 32-bit: low 4 bits = argbytes/4 (stack arg count), upper
 * 28 bits = signed RVA from KiServiceTable base.
 */
UINT64
KiResolveSyscallByNumber(
    IN UINT64 service_table_va,
    IN UINT16 syscall_num
    )
{
    if (service_table_va == 0) return 0;
    INT32 entry = *(INT32 *)(UINTN)(service_table_va + (UINT64)syscall_num * 4);
    INT64 sext_rva = (INT64)(entry >> 4);
    return service_table_va + sext_rva;
}

/*
 * One-shot resolver: image-base + syscall # -> body VA.
 * Returns 0 on failure.
 */
UINT64
KiResolveNtBody(
    IN UINT8  *ntos_base,
    IN UINTN   ntos_size,
    IN UINT16  syscall_num
    )
{
    UINT64 service_table = KiResolveServiceTable(ntos_base, ntos_size);
    if (service_table == 0) {
        Print(L"[KiResolve] KiServiceTable not found\n");
        return 0;
    }
    UINT64 body_va = KiResolveSyscallByNumber(service_table, syscall_num);
    Print(L"[KiResolve] syscall 0x%x -> body @ 0x%llx\n",
          (UINT32)syscall_num, body_va);
    return body_va;
}

/*
 * Validate body looks like a real Nt body (not pointing into garbage).
 * Real Nt bodies start with one of:
 *   48 89 5C 24 ??       mov [rsp+??], rbx
 *   48 8B C4             mov rax, rsp
 *   48 81 EC ?? ?? ?? ?? sub rsp, imm32
 *   40 53                push rbx
 *   40 55                push rbp
 *   48 83 EC             sub rsp, imm8
 */
BOOLEAN
KiValidateNtBodyPrologue(IN UINT64 body_va)
{
    if (body_va == 0) return FALSE;
    UINT8 *p = (UINT8 *)(UINTN)body_va;

    // Pattern 1: 48 89 5C 24 ??
    if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24) return TRUE;
    // Pattern 2: 48 8B C4
    if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4) return TRUE;
    // Pattern 3: 48 81 EC
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) return TRUE;
    // Pattern 4: 40 53 / 40 55
    if (p[0] == 0x40 && (p[1] == 0x53 || p[1] == 0x55)) return TRUE;
    // Pattern 5: 48 83 EC
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return TRUE;

    Print(L"[KiResolve] body prologue mismatch @ 0x%llx: %02x %02x %02x %02x\n",
          body_va, p[0], p[1], p[2], p[3]);
    return FALSE;
}

VOID *
ResolveNtCreateProfile(VOID)
{
    // Phase 4: locate ntos via VMM exit-time RIP unwinding, then call
    // KiResolveNtBody(ntos_base, ntos_size, kNtosBuilds[i].nt_create_profile_syscall_num).
    return NULL;
}
