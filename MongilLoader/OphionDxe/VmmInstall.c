/*
 * VmmInstall.c — Phase 4d-i: write Ophion inline patch into ntos.text from
 * VMX-root via guest CR3 PT walk + host-CR3 identity write.
 *
 * Why no CR0.WP toggle: our flat 1GB-identity host CR3 sets PTE.RW on every
 * 1GB page, so writes via host-VA (= host-PA = guest-PA after PT-walk) bypass
 * the guest's read-only ntos.text mapping entirely.
 *
 * Why no EPT cloak (deferred to Phase 4d-ii): EPT identity-RWX so writes
 * through host CR3 hit guest physical RAM directly. PatchGuard 0x109 BSOD is
 * possible after PG's next scan (typically minutes); first end-to-end test is
 * intentionally short to fit in that window. Phase 4d-ii adds 4KB-split + EPT
 * exec-only + read-shadow to survive PG.
 *
 * Defensive checks before write:
 *   - trampoline_built == 1
 *   - resolve flags include PROL_OK
 *   - current 14 bytes at NCP_VA still == g_saved_prologue (no race / external
 *     patch since resolve)
 *
 * Status codes:
 *   0  ok
 *   1  no trampoline
 *   2  no NCP target
 *   3  prologue mismatch (already patched / wrong VA)
 *   4  short write
 *   5  short readback
 *   6  readback mismatch (write didn't stick)
 */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <intrin.h>

#include "EfiCompat.h"
#include "ia32.h"

#define INSTALL_OVERWRITE_BYTES 14

extern UINT8 *g_trampoline_page;
extern UINT64 g_trampoline_va;
extern UINT32 g_trampoline_built;
extern UINT8  g_saved_prologue[14];

extern UINTN vmm_guest_read(UINT64 cr3, UINT64 va, VOID *dst, UINTN size);
extern UINTN vmm_guest_write(UINT64 cr3, UINT64 va, CONST VOID *src, UINTN size);
extern VOID  NtosBuildInlinePatch(UINT8 out[14], UINT64 trampoline_va);
extern UINT64 ophion_resolve_get_ncp_va(VOID);
extern UINT32 ophion_resolve_flags(VOID);

#define RESOLVE_NCP_PROLOGUE_OK  (1U << 3)

static UINT32 g_install_attempted = 0;
static UINT32 g_install_status    = 0xFF;
static UINT8  g_inline_patch[INSTALL_OVERWRITE_BYTES];
static UINT8  g_pre_read[INSTALL_OVERWRITE_BYTES];
static UINT8  g_post_read[INSTALL_OVERWRITE_BYTES];

UINT32
ophion_install_do(UINT64 cr3)
{
    if (g_install_attempted) return g_install_status;
    g_install_attempted = 1;

    if (!g_trampoline_built || g_trampoline_va == 0) {
        g_install_status = 1;
        return 1;
    }

    UINT64 ncp_va = ophion_resolve_get_ncp_va();
    UINT32 flags  = ophion_resolve_flags();
    if (ncp_va == 0 || !(flags & RESOLVE_NCP_PROLOGUE_OK)) {
        g_install_status = 2;
        return 2;
    }

    // Read current bytes — verify no external patch / race.
    if (vmm_guest_read(cr3, ncp_va, g_pre_read, INSTALL_OVERWRITE_BYTES) !=
        INSTALL_OVERWRITE_BYTES) {
        g_install_status = 3;
        return 3;
    }
    for (UINTN i = 0; i < INSTALL_OVERWRITE_BYTES; i++) {
        if (g_pre_read[i] != g_saved_prologue[i]) {
            g_install_status = 3;
            return 3;
        }
    }

    // Build inline patch (mov rax,trampoline_va; jmp rax; nop nop).
    NtosBuildInlinePatch(g_inline_patch, g_trampoline_va);

    // Write.
    UINTN w = vmm_guest_write(cr3, ncp_va, g_inline_patch, INSTALL_OVERWRITE_BYTES);
    if (w != INSTALL_OVERWRITE_BYTES) {
        g_install_status = 4;
        return 4;
    }

    // Verify.
    UINTN r = vmm_guest_read(cr3, ncp_va, g_post_read, INSTALL_OVERWRITE_BYTES);
    if (r != INSTALL_OVERWRITE_BYTES) {
        g_install_status = 5;
        return 5;
    }
    for (UINTN i = 0; i < INSTALL_OVERWRITE_BYTES; i++) {
        if (g_post_read[i] != g_inline_patch[i]) {
            g_install_status = 6;
            return 6;
        }
    }

    g_install_status = 0;
    return 0;
}

VOID
ophion_install_get(UINT32 subleaf,
                   UINT32 *out_eax, UINT32 *out_ebx,
                   UINT32 *out_ecx, UINT32 *out_edx)
{
    *out_eax = 0x4F504858;  // 'OPHX' ack
    switch (subleaf) {
    case 0:
        *out_ebx = g_install_status;
        *out_ecx = g_install_attempted;
        *out_edx = (UINT32)g_trampoline_va;
        break;
    case 1:
        *out_ebx = *(UINT32 *)&g_inline_patch[0];
        *out_ecx = *(UINT32 *)&g_inline_patch[4];
        *out_edx = ((UINT32)g_inline_patch[8])         |
                   ((UINT32)g_inline_patch[9]  << 8)   |
                   ((UINT32)g_inline_patch[10] << 16)  |
                   ((UINT32)g_inline_patch[11] << 24);
        break;
    case 2:
        *out_ebx = *(UINT32 *)&g_post_read[0];
        *out_ecx = *(UINT32 *)&g_post_read[4];
        *out_edx = ((UINT32)g_post_read[8])         |
                   ((UINT32)g_post_read[9]  << 8)   |
                   ((UINT32)g_post_read[10] << 16)  |
                   ((UINT32)g_post_read[11] << 24);
        break;
    case 3:
        // Pre-read (what was there before install).
        *out_ebx = *(UINT32 *)&g_pre_read[0];
        *out_ecx = *(UINT32 *)&g_pre_read[4];
        *out_edx = ((UINT32)g_pre_read[8])         |
                   ((UINT32)g_pre_read[9]  << 8)   |
                   ((UINT32)g_pre_read[10] << 16)  |
                   ((UINT32)g_pre_read[11] << 24);
        break;
    default:
        *out_eax = 0;
        *out_ebx = 0;
        *out_ecx = 0;
        *out_edx = 0;
        break;
    }
}

//
// Phase 7d step 6: cloaked install.
//
// Patches the alt copy ONLY. Real ntos.text bytes untouched on the physical
// page. EPT cloak then routes:
//   - exec fetches at NCP_VA → alt_pfn (patched bytes) → jmp to trampoline
//   - reads (PG SHA hash) → real_pfn (clean bytes) via EPT_VIOLATION + MTF
// This survives PatchGuard on a system without EfiGuard.
//
// Status codes:
//   0  ok
//   1  no trampoline
//   2  no NCP target
//   3  prologue mismatch (already patched / wrong VA)
//   4  alt page alloc failed
//   5  PT walk failed for ntos.text page
//   6  cross-page (NCP straddles 4KB boundary — refuse, would need 2 cloaks)
//   7  EPT cloak install failed
//
extern PVOID  EfiAllocateRuntimePages(UINTN Pages);
extern UINT64 va_to_pa(PVOID va);
extern UINT64 vmm_pt_walk(UINT64 cr3, UINT64 va);
extern VOID  *ept_install_cloak(UINT64 target_gphys, UINT64 alt_pfn);
extern UINT8 *ept_take_preallocated_alt_page(VOID);

static UINT32 g_cloak_install_attempted = 0;
static UINT32 g_cloak_install_status    = 0xFF;
static UINT64 g_cloak_target_gphys      = 0;
static UINT64 g_cloak_alt_pfn           = 0;

UINT32
ophion_install_do_cloaked(UINT64 cr3)
{
    // Allow retry if previous attempt failed (status != 0). Prevents
    // sticky-fail when first attempt had wrong RVA / unbuilt trampoline
    // and user fixes state then retries.
    if (g_cloak_install_attempted && g_cloak_install_status == 0)
        return 0;
    g_cloak_install_attempted = 1;

    if (!g_trampoline_built || g_trampoline_va == 0) {
        g_cloak_install_status = 1;
        return 1;
    }

    UINT64 ncp_va = ophion_resolve_get_ncp_va();
    UINT32 flags  = ophion_resolve_flags();
    if (ncp_va == 0 || !(flags & RESOLVE_NCP_PROLOGUE_OK)) {
        g_cloak_install_status = 2;
        return 2;
    }

    // Sanity: prologue must still match saved bytes.
    if (vmm_guest_read(cr3, ncp_va, g_pre_read, INSTALL_OVERWRITE_BYTES) !=
        INSTALL_OVERWRITE_BYTES) {
        g_cloak_install_status = 3;
        return 3;
    }
    for (UINTN i = 0; i < INSTALL_OVERWRITE_BYTES; i++) {
        if (g_pre_read[i] != g_saved_prologue[i]) {
            g_cloak_install_status = 3;
            return 3;
        }
    }

    // Refuse if patch straddles 4KB page boundary — cloak protects one page.
    UINT64 page_off = ncp_va & 0xFFFULL;
    if (page_off + INSTALL_OVERWRITE_BYTES > 0x1000) {
        g_cloak_install_status = 6;
        return 6;
    }

    // Resolve real ntos.text page physical address via guest PT walk.
    UINT64 ncp_va_page = ncp_va & ~0xFFFULL;
    UINT64 ncp_pa_page = vmm_pt_walk(cr3, ncp_va_page);
    if (ncp_pa_page == 0) {
        g_cloak_install_status = 5;
        return 5;
    }

    // Alloc alt page from pre-allocated pool (DXE-entry alloc; VMX-root cannot
    // call gBS post-EBS). Copy clean bytes (full 4KB) from real ntos.text.
    UINT8 *alt_page = ept_take_preallocated_alt_page();
    if (!alt_page) {
        g_cloak_install_status = 4;
        return 4;
    }
    UINT8 *real_host = (UINT8 *)(UINTN)ncp_pa_page;  // host CR3 identity-maps phys
    CopyMem(alt_page, real_host, 0x1000);

    // Build inline patch (mov rax,trampoline_va; jmp rax; nop nop) into alt.
    NtosBuildInlinePatch(g_inline_patch, g_trampoline_va);
    CopyMem(alt_page + page_off, g_inline_patch, INSTALL_OVERWRITE_BYTES);

    UINT64 alt_pfn = va_to_pa(alt_page) >> 12;

    // Commit cloak: PML1 entry for ncp_pa_page → exec-only on alt_pfn.
    if (!ept_install_cloak(ncp_pa_page, alt_pfn)) {
        g_cloak_install_status = 7;
        return 7;
    }

    g_cloak_target_gphys = ncp_pa_page;
    g_cloak_alt_pfn      = alt_pfn;
    g_cloak_install_status = 0;
    return 0;
}

VOID
ophion_install_cloak_get(UINT32 subleaf,
                         UINT32 *out_eax, UINT32 *out_ebx,
                         UINT32 *out_ecx, UINT32 *out_edx)
{
    *out_eax = 0x4F504858;  // 'OPHX' ack
    switch (subleaf) {
    case 0:
        *out_ebx = g_cloak_install_status;
        *out_ecx = g_cloak_install_attempted;
        *out_edx = 0;
        break;
    case 1:
        *out_ebx = (UINT32)g_cloak_target_gphys;
        *out_ecx = (UINT32)(g_cloak_target_gphys >> 32);
        *out_edx = (UINT32)g_cloak_alt_pfn;
        break;
    default:
        *out_eax = 0;
        *out_ebx = 0;
        *out_ecx = 0;
        *out_edx = 0;
        break;
    }
}
