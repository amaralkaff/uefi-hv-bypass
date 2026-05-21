/*
 * VmmResolveNtos.c - resolve ntoskrnl base + KiServiceTable + NtCreateProfile
 * from VMX-root context using guest CR3 + IA32_LSTAR walk-back.
 *
 * Phase 4a strategy:
 *   1. Read MSR_LSTAR = guest's KiSystemCall64SwapGs entry. NT writes this
 *      MSR via wrmsr at boot; our MSR bitmap is zeroed so writes pass through
 *      to physical MSR. At any vmexit, __readmsr(LSTAR) returns NT's value.
 *   2. Walk back page-aligned from LSTAR looking for MZ+PE signature. Cap
 *      walk at 16MB (typical ntoskrnl < 12MB).
 *   3. Once base found, read SizeOfImage from PE header.
 *   4. Sig-scan ntos.text for KiSystemCall64 LEA r10/r11 pair → KiServiceTable.
 *   5. Decode service table entry [syscall_num] → NtXxx body VA.
 *   6. Validate NtXxx body has known prologue pattern.
 *   7. Cache results in g_rs; subsequent CPUID OPHR returns cached.
 *
 * All reads via vmm_guest_read using guest CR3 (translates GVA → GPA via
 * 4-level walk; GPA → host VA via flat 1GB-identity host CR3 since 12GB RAM
 * fits in 0-512GB host identity coverage).
 */
#include <Uefi.h>
#include <intrin.h>

#include "EfiCompat.h"
#include "ia32.h"

extern UINT64 vmm_pt_walk(UINT64 cr3, UINT64 va);
extern UINTN  vmm_guest_read(UINT64 cr3, UINT64 va, VOID *dst, UINTN size);
extern UINT16 vmm_guest_read16(UINT64 cr3, UINT64 va);
extern UINT32 vmm_guest_read32(UINT64 cr3, UINT64 va);
extern UINT64 vmm_guest_read64(UINT64 cr3, UINT64 va);

extern UINTN NtosBuildTrampoline(IN UINT8 *out, IN UINT64 nt_va,
                                 IN CONST UINT8 *saved);

// Phase 4b: pre-allocated trampoline page (set at DXE entry, populated when
// OPHS resolves target). Lives in EfiRuntimeServicesCode so it survives EBS.
//
// Phase 4d-iii: split into multiple representations:
//   - g_trampoline_page : raw EfiAllocateRuntimePages return; phys-identity
//     pointer used for VMM-side writes (host CR3 flat 1GB identity maps phys
//     to host VA 1:1, valid forever).
//   - g_trampoline_nt_ptr: alias of same alloc; gets ConvertPointer-ed by
//     SetVirtualAddressMap during winload → becomes NT-side kernel VA.
//   - g_trampoline_va: tracks current valid VA for guest-context use; pre-SVM
//     = phys, post-SVM = NT VA. Used in inline-jmp patch encoding.
//   - g_trampoline_phys: immutable phys for diagnostic readback.
UINT8 *g_trampoline_page  = NULL;
VOID  *g_trampoline_nt_ptr = NULL;
UINT64 g_trampoline_phys  = 0;
UINT64 g_trampoline_va    = 0;
UINTN  g_trampoline_size  = 0;
UINT8  g_saved_prologue[14];
UINT32 g_trampoline_built = 0;

#define IA32_LSTAR  0xC0000082

#define RESOLVE_NTOS_FOUND       (1U << 0)
#define RESOLVE_SVCTBL_FOUND     (1U << 1)
#define RESOLVE_NCP_FOUND        (1U << 2)
#define RESOLVE_NCP_PROLOGUE_OK  (1U << 3)

#define NTCP_SYSCALL_NUM   0xBB     // NtCreateProfile (resolve_syscall.py output)

typedef struct {
    UINT64 guest_cr3;
    UINT64 lstar;
    UINT64 ntos_base;
    UINT32 ntos_size;
    UINT32 flags;
    UINT64 service_table;
    UINT64 nt_create_profile;
    UINT32 resolved;        // 0 = not tried, 1 = tried (success or failure latched)
    UINT32 walked_pages;    // diagnostic: pages walked during ntos scan
} OPHION_RESOLVE_STATE;

static OPHION_RESOLVE_STATE g_rs;

static UINT64
ntos_walk_back(UINT64 cr3, UINT64 lstar, UINT32 *out_walked)
{
    UINT64 page = lstar & ~0xFFFULL;
    // Walk up to 64MB back. Kernel ASLR can place ntoskrnl far below LSTAR
    // when smaller modules (hal.dll, mcupdate, etc.) load between them.
    UINT64 floor = (page > 0x4000000ULL) ? (page - 0x4000000ULL) : 0;
    UINT32 walked = 0;
    while (page >= floor && walked < 0x4000) {
        walked++;
        UINT16 mz = vmm_guest_read16(cr3, page);
        if (mz == 0x5A4D) {
            UINT32 e_lfanew = vmm_guest_read32(cr3, page + 0x3C);
            if (e_lfanew > 0 && e_lfanew < 0x1000) {
                UINT32 pe = vmm_guest_read32(cr3, page + e_lfanew);
                if (pe == 0x00004550) {
                    // Phase 4a-iii: validate this PE actually contains LSTAR.
                    // Phase 4a-ii hit hal.dll at 0xfffff804361fa000 (size 0x8a000)
                    // because LSTAR was past its end. Reject and keep walking.
                    UINT32 sz = vmm_guest_read32(cr3, page + e_lfanew + 0x50);
                    if (sz > 0 && (page + (UINT64)sz) > lstar) {
                        if (out_walked) *out_walked = walked;
                        return page;
                    }
                }
            }
        }
        if (page < 0x1000) break;
        page -= 0x1000;
    }
    if (out_walked) *out_walked = walked;
    return 0;
}

//
// Find KiServiceTable by walking forward from LSTAR. LSTAR points at the
// actual syscall entry (KiSystemCall64 or KiSystemCall64Shadow depending on
// KVAS mitigation).
//
// On Win10 19045 the canonical pair is:
//   lea r10, [KiServiceTable]    ; 4C 8D 15 ?? ?? ?? ??
//   lea r11, [KiArgumentTable]   ; 4C 8D 1D ?? ?? ?? ??
//
// BUT inspection on i5-12400F bare metal showed the LEA pair encountered
// has r10 → KiArgumentTable (byte array) and r11 → KiServiceTable. Phase
// 4a-viii used r10's disp and decoded entry[0] = 0x1bec7a10 = byte values
// 10 7a ec 1b in little-endian (10 = argbytes for NtAccessCheck = correct
// for KiArgumentTable). Phase 4a-ix uses r11's disp instead. Function VAs
// are 8-byte stride.
//
static UINT64
service_table_scan_from_lstar(UINT64 cr3, UINT64 lstar)
{
    UINT8 win[0x10];
    for (UINT32 fwd = 0; fwd < 0x800; fwd++) {
        UINT64 va = lstar + fwd;
        if (vmm_guest_read(cr3, va, win, sizeof(win)) != sizeof(win)) continue;
        if (win[0] != 0x4C || win[1] != 0x8D || win[2] != 0x15) continue;
        if (win[7] != 0x4C || win[8] != 0x8D || win[9] != 0x1D) continue;
        // Use lea r11's disp32 — that's the real KiServiceTable on this build.
        // RIP for r11 = va + 7 (start of 2nd LEA) + 7 (length) = va + 14.
        INT32 disp_r11 = *(INT32 *)&win[10];
        return (va + 14) + (INT64)disp_r11;
    }
    return 0;
}

static UINT64
syscall_resolve(UINT64 cr3, UINT64 svctbl_va, UINT16 syscall_num)
{
    if (svctbl_va == 0) return 0;
    // Win10 19045 KiServiceTable is 8-byte-stride array of full 64-bit
    // function VAs. The compact (rva << 4 | argbytes) encoding documented
    // for older builds is NOT used here — verified via diagnostic CPUID
    // subleaf 5/7: entry[0] = NtAccessCheck low-32 with high-32 (0xfffff806)
    // sitting at +4. Stride 4 produced entry[0xBB]=0 because read landed
    // mid-entry on the high-half of a different syscall.
    return vmm_guest_read64(cr3, svctbl_va + (UINT64)syscall_num * 8);
}

static BOOLEAN
nt_body_prologue_ok(UINT64 cr3, UINT64 body_va)
{
    if (body_va == 0) return FALSE;
    UINT8 p[8];
    if (vmm_guest_read(cr3, body_va, p, sizeof(p)) != sizeof(p)) return FALSE;
    if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24) return TRUE;
    if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4) return TRUE;
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) return TRUE;
    if (p[0] == 0x40 && (p[1] == 0x53 || p[1] == 0x55)) return TRUE;
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return TRUE;
    return FALSE;
}

VOID
ophion_resolve_all_once(UINT64 guest_cr3)
{
    if (g_rs.resolved) return;
    g_rs.resolved = 1;
    g_rs.guest_cr3 = guest_cr3;
    g_rs.lstar = __readmsr(IA32_LSTAR);
    if (g_rs.lstar == 0) return;

    UINT32 walked = 0;
    g_rs.ntos_base = ntos_walk_back(guest_cr3, g_rs.lstar, &walked);
    g_rs.walked_pages = walked;
    if (g_rs.ntos_base == 0) return;
    g_rs.flags |= RESOLVE_NTOS_FOUND;

    UINT32 e_lfanew = vmm_guest_read32(guest_cr3, g_rs.ntos_base + 0x3C);
    if (e_lfanew == 0 || e_lfanew > 0x1000) return;
    g_rs.ntos_size = vmm_guest_read32(guest_cr3, g_rs.ntos_base + e_lfanew + 0x50);
    if (g_rs.ntos_size == 0 || g_rs.ntos_size > 32 * 1024 * 1024) return;

    g_rs.service_table = service_table_scan_from_lstar(guest_cr3, g_rs.lstar);
    if (g_rs.service_table == 0) return;
    g_rs.flags |= RESOLVE_SVCTBL_FOUND;

    g_rs.nt_create_profile = syscall_resolve(guest_cr3, g_rs.service_table, NTCP_SYSCALL_NUM);
    if (g_rs.nt_create_profile == 0) return;
    g_rs.flags |= RESOLVE_NCP_FOUND;

    if (nt_body_prologue_ok(guest_cr3, g_rs.nt_create_profile))
        g_rs.flags |= RESOLVE_NCP_PROLOGUE_OK;
}

//
// Phase 4a-x: user-mode override. Cheat exe supplies NtCreateProfile RVA
// (relative to ntos_base) via CPUID 0x4F504853 'OPHS' with ecx=RVA. VMM
// validates rva is in-range, computes VA, body-prologue-checks via guest
// read, caches into g_rs. Pivot from VMM-side KiServiceTable scan because
// disambiguating LEA r10/r11 pairs in KiSystemCall64Shadow without PDB
// reliably is impossible from VMX-root.
//
// User-mode obtains RVA by parsing C:\Windows\System32\ntoskrnl.exe via
// dbghelp + Microsoft symbol server (next reboot has the C tool wired in).
//
UINT64
ophion_resolve_get_ncp_va(VOID)
{
    return g_rs.nt_create_profile;
}

UINT32
ophion_resolve_flags(VOID)
{
    return g_rs.flags;
}

UINT32
ophion_resolve_set_ncp(UINT64 cr3, UINT32 rva)
{
    if (g_rs.ntos_base == 0) return g_rs.flags;
    if (rva == 0 || rva >= g_rs.ntos_size) return g_rs.flags;

    UINT64 va = g_rs.ntos_base + (UINT64)rva;
    g_rs.nt_create_profile = va;
    g_rs.flags |= RESOLVE_NCP_FOUND;

    if (!nt_body_prologue_ok(cr3, va)) {
        g_rs.flags &= ~(UINT32)RESOLVE_NCP_PROLOGUE_OK;
        return g_rs.flags;
    }
    g_rs.flags |= RESOLVE_NCP_PROLOGUE_OK;

    // Phase 4b: build trampoline now that target VA is locked. Prerequisites:
    //   - g_trampoline_page allocated at DXE entry (EfiRuntimeServicesCode)
    //   - target prologue is real Nt body (passed prologue check above)
    //
    // Phase 4d-iii: writes go through g_trampoline_page (phys-identity, valid
    // in VMM host CR3 forever). Patch ENCODING uses g_trampoline_va which the
    // VirtualAddressChange callback has converted to NT-side kernel VA.
    if (g_trampoline_page != NULL && !g_trampoline_built) {
        if (vmm_guest_read(cr3, va, g_saved_prologue, 14) == 14) {
            g_trampoline_size = NtosBuildTrampoline(g_trampoline_page, va, g_saved_prologue);
            // g_trampoline_va already set by VirtAddrChangeNotify (post-SVM)
            // or DXE entry (pre-SVM identity). Don't overwrite here.
            g_trampoline_built = 1;
        }
    }
    return g_rs.flags;
}

VOID
ophion_resolve_get(UINT32 subleaf,
                   UINT32 *out_eax, UINT32 *out_ebx,
                   UINT32 *out_ecx, UINT32 *out_edx){
    *out_eax = 0x4F504852;  // 'OPHR' ack
    switch (subleaf) {
    case 0:
        *out_ebx = (UINT32)g_rs.ntos_base;
        *out_ecx = (UINT32)(g_rs.ntos_base >> 32);
        *out_edx = g_rs.ntos_size;
        break;
    case 1:
        *out_ebx = (UINT32)g_rs.nt_create_profile;
        *out_ecx = (UINT32)(g_rs.nt_create_profile >> 32);
        *out_edx = g_rs.flags;
        break;
    case 2:
        *out_ebx = (UINT32)g_rs.service_table;
        *out_ecx = (UINT32)(g_rs.service_table >> 32);
        *out_edx = (UINT32)g_rs.lstar;
        break;
    case 3:
        *out_ebx = (UINT32)g_rs.guest_cr3;
        *out_ecx = (UINT32)(g_rs.guest_cr3 >> 32);
        *out_edx = (UINT32)(g_rs.lstar >> 32);
        break;
    case 4:
        *out_ebx = g_rs.walked_pages;
        *out_ecx = g_rs.resolved;
        *out_edx = g_rs.flags;
        break;
    case 5: {
        // Diagnostic: raw entry[0] + entry[0xBB] from KiServiceTable (8-byte
        // stride). entry[0] = NtAccessCheck VA. entry[0xBB] = NtCreateProfile.
        // Return low 32 bits of each in ebx/ecx; svctbl offset in edx for
        // sanity. Phase 4a-vii fixed stride from 4 to 8.
        UINT64 e0 = 0, ebb = 0;
        if (g_rs.service_table) {
            e0  = vmm_guest_read64(g_rs.guest_cr3, g_rs.service_table + 0);
            ebb = vmm_guest_read64(g_rs.guest_cr3, g_rs.service_table + 0xBB * 8);
        }
        *out_ebx = (UINT32)e0;
        *out_ecx = (UINT32)ebb;
        *out_edx = (UINT32)(g_rs.service_table - g_rs.ntos_base);
        break;
    }
    case 6: {
        // Diagnostic: first 8 bytes at LSTAR — confirms KiSystemCall64
        // entry sequence (swapgs / save rsp / etc.).
        UINT8 b[8] = {0};
        vmm_guest_read(g_rs.guest_cr3, g_rs.lstar, b, 8);
        *out_ebx = ((UINT32)b[3] << 24) | ((UINT32)b[2] << 16) |
                   ((UINT32)b[1] << 8)  |  (UINT32)b[0];
        *out_ecx = ((UINT32)b[7] << 24) | ((UINT32)b[6] << 16) |
                   ((UINT32)b[5] << 8)  |  (UINT32)b[4];
        *out_edx = 0;
        break;
    }
    case 7: {
        // Diagnostic: entry[0x18] (NtAllocateVirtualMemory) +
        // entry[0xF] (NtClose) — both heavily used, must be valid.
        UINT64 e18 = 0, ef = 0;
        if (g_rs.service_table) {
            e18 = vmm_guest_read64(g_rs.guest_cr3, g_rs.service_table + 0x18 * 8);
            ef  = vmm_guest_read64(g_rs.guest_cr3, g_rs.service_table + 0xF * 8);
        }
        *out_ebx = (UINT32)e18;
        *out_ecx = (UINT32)ef;
        *out_edx = 0;
        break;
    }
    case 8:
        // Trampoline VA + size + built flag. VA = NT-side post-SVM.
        *out_ebx = (UINT32)g_trampoline_va;
        *out_ecx = (UINT32)(g_trampoline_va >> 32);
        *out_edx = ((UINT32)g_trampoline_size & 0xFFFF) |
                   ((g_trampoline_built & 1) << 31);
        break;
    case 9: {
        // First 16 bytes of trampoline (verifies page contents).
        if (g_trampoline_built && g_trampoline_page) {
            *out_ebx = *(UINT32 *)&g_trampoline_page[0];
            *out_ecx = *(UINT32 *)&g_trampoline_page[4];
            *out_edx = *(UINT32 *)&g_trampoline_page[8];
        } else {
            *out_ebx = 0; *out_ecx = 0; *out_edx = 0;
        }
        break;
    }
    case 10: {
        // First 14 saved prologue bytes (verifies VMM read original ntos.text).
        *out_ebx = *(UINT32 *)&g_saved_prologue[0];
        *out_ecx = *(UINT32 *)&g_saved_prologue[4];
        *out_edx = ((UINT32)g_saved_prologue[8])         |
                   ((UINT32)g_saved_prologue[9]  << 8)   |
                   ((UINT32)g_saved_prologue[10] << 16)  |
                   ((UINT32)g_saved_prologue[11] << 24);
        break;
    }
    case 11:
        // Phase 4d-iii: trampoline phys (immutable) for delta vs g_trampoline_va.
        // If post-SVM, g_trampoline_va != g_trampoline_phys.
        *out_ebx = (UINT32)g_trampoline_phys;
        *out_ecx = (UINT32)(g_trampoline_phys >> 32);
        *out_edx = (g_trampoline_va == g_trampoline_phys) ? 0 : 1; // 1 = converted
        break;
    case 12: {
        // Phase 5b: kernel offsets state. ebx:ecx = PsActiveProcessHead VA,
        // edx = packed flags + offsets summary.
        extern UINT64 g_ps_active_process_head_va;
        extern UINT16 g_off_active_process_links;
        extern UINT16 g_off_unique_process_id;
        extern UINT32 g_kernel_offsets_set;
        *out_ebx = (UINT32)g_ps_active_process_head_va;
        *out_ecx = (UINT32)(g_ps_active_process_head_va >> 32);
        *out_edx = ((UINT32)g_off_active_process_links << 16) |
                   ((UINT32)g_off_unique_process_id & 0xFFFF) |
                   ((g_kernel_offsets_set & 1) << 31);
        break;
    }
    case 13: {
        // Phase 5c diag: walk state. ebx:ecx = first_link from head,
        // edx = iter count.
        extern UINT64 g_resolve_first_link;
        extern UINT32 g_resolve_iter_count;
        *out_ebx = (UINT32)g_resolve_first_link;
        *out_ecx = (UINT32)(g_resolve_first_link >> 32);
        *out_edx = g_resolve_iter_count;
        break;
    }
    case 14: {
        // Phase 5c diag: caller_cr3 + last_eproc.
        extern UINT64 g_resolve_last_cr3;
        extern UINT64 g_resolve_last_eproc;
        *out_ebx = (UINT32)g_resolve_last_cr3;
        *out_ecx = (UINT32)(g_resolve_last_cr3 >> 32);
        *out_edx = (UINT32)g_resolve_last_eproc;
        break;
    }
    case 15: {
        // Phase 5c diag: last 12 bytes of EPROCESS.ImageFileName seen.
        extern UINT8 g_resolve_last_name[16];
        *out_ebx = *(UINT32 *)&g_resolve_last_name[0];
        *out_ecx = *(UINT32 *)&g_resolve_last_name[4];
        *out_edx = *(UINT32 *)&g_resolve_last_name[8];
        break;
    }
    case 16: {
        // Phase 5e diag: VMCALL RIP-gate state.
        extern UINT32 g_vmcall_rip_rejects;
        extern UINT64 g_vmcall_last_bad_rip;
        *out_ebx = g_vmcall_rip_rejects;
        *out_ecx = (UINT32)g_vmcall_last_bad_rip;
        *out_edx = (UINT32)(g_vmcall_last_bad_rip >> 32);
        break;
    }
    case 17: {
        // Phase 5f diag: last REGISTER text hash + size.
        extern UINT8  g_last_register_hash[32];
        extern UINT64 g_last_register_text_va;
        extern UINT32 g_last_register_text_size;
        *out_ebx = (UINT32)g_last_register_text_va;
        *out_ecx = (UINT32)(g_last_register_text_va >> 32);
        *out_edx = g_last_register_text_size;
        break;
    }
    case 18: {
        // Phase 5f diag: hash bytes 0..11 (first 12 bytes).
        extern UINT8 g_last_register_hash[32];
        *out_ebx = *(UINT32 *)&g_last_register_hash[0];
        *out_ecx = *(UINT32 *)&g_last_register_hash[4];
        *out_edx = *(UINT32 *)&g_last_register_hash[8];
        break;
    }
    case 19: {
        // Phase 5f diag: hash bytes 12..23.
        extern UINT8 g_last_register_hash[32];
        *out_ebx = *(UINT32 *)&g_last_register_hash[12];
        *out_ecx = *(UINT32 *)&g_last_register_hash[16];
        *out_edx = *(UINT32 *)&g_last_register_hash[20];
        break;
    }
    case 20: {
        // Phase 5f diag: hash bytes 24..31 + magic 'F' marker.
        extern UINT8 g_last_register_hash[32];
        *out_ebx = *(UINT32 *)&g_last_register_hash[24];
        *out_ecx = *(UINT32 *)&g_last_register_hash[28];
        *out_edx = 0x46414C53; // 'SLAF' marker (LE: 'FALS' read backward = 5F debug)
        break;
    }
    default:
        *out_eax = 0;
        *out_ebx = 0;
        *out_ecx = 0;
        *out_edx = 0;
        break;
    }
}
