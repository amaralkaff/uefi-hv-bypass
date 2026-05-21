/*
 * NtosPatch.c - NtCreateProfile prologue trampoline writer (Phase 4)
 *
 * Patches NtCreateProfile body's first 14 bytes with an absolute jmp into
 * a trampoline allocated in EfiRuntimeServicesCode. The trampoline checks
 * for OPHION_VMCALL_MAGIC_HANDLE in rcx; on match, dispatches to VMM via
 * VMCALL. On miss, executes the saved 14 bytes and jmps back to
 * NtCreateProfile + 14.
 *
 * Patch layout (14 bytes overwrite at NtCreateProfile body entry):
 *   48 B8 <8-byte-trampoline-va>     mov rax, trampoline_va
 *   FF E0                            jmp rax
 *
 * Trampoline layout (~64 bytes, allocated in EfiRuntimeServicesCode):
 *   ; magic check
 *   49 BA <8-byte-magic>             mov r10, OPHION_VMCALL_MAGIC_HANDLE
 *   4C 39 D1                         cmp rcx, r10
 *   75 13                            jne short fall_through  (skip 19 bytes)
 *
 *   ; magic match: shuffle args + VMCALL
 *   48 89 D0                         mov rax, rdx   (session_key)
 *   4C 89 C2                         mov rdx, r8    (op)
 *   4D 89 C8                         mov r8, r9     (buffer va)
 *   4C 8B 4C 24 28                   mov r9, [rsp+0x28]  (buffer size)
 *   0F 01 C1                         vmcall
 *   C3                               ret
 *
 *   ; fall_through: replay original 14 bytes + jmp to body+14
 *   <14 bytes of saved original>
 *   48 B8 <8-byte-resume-va>         mov rax, NtCreateProfile + 14
 *   FF E0                            jmp rax
 *
 * Total trampoline = 13 (magic check) + 19 (vmcall path) + 14 (saved) +
 *                    12 (resume jmp) = 58 bytes. Fits in one EFI page.
 */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>

#include "EfiCompat.h"

#define OPHION_VMCALL_MAGIC_HANDLE_U64  0xCAFEDEADBEEF1234ULL

#define NTOS_PATCH_OVERWRITE_BYTES 14
#define TRAMPOLINE_SIZE            64

extern PVOID EfiAllocateRuntimePages(SIZE_T Pages);

/*
 * Build the trampoline bytes into `out` (must be >= TRAMPOLINE_SIZE).
 *
 * Args:
 *   nt_create_profile_va : VA of NtCreateProfile body in ntoskrnl (target of
 *                          the patch; resume_va = nt_create_profile_va + 14)
 *   saved_prologue       : caller-supplied 14 bytes captured before patching
 *
 * Returns the count of bytes written (always TRAMPOLINE_SIZE).
 */
UINTN
NtosBuildTrampoline(
    IN  UINT8  *out,
    IN  UINT64  nt_create_profile_va,
    IN  CONST UINT8 *saved_prologue
    )
{
    UINTN n = 0;

    // mov r10, OPHION_VMCALL_MAGIC_HANDLE
    out[n++] = 0x49; out[n++] = 0xBA;
    UINT64 magic = OPHION_VMCALL_MAGIC_HANDLE_U64;
    CopyMem(&out[n], &magic, 8); n += 8;

    // cmp rcx, r10
    out[n++] = 0x4C; out[n++] = 0x39; out[n++] = 0xD1;

    // jne short fall_through (skip 18 bytes: the magic-match path below)
    out[n++] = 0x75; out[n++] = 0x12;

    // mov rax, rdx
    out[n++] = 0x48; out[n++] = 0x89; out[n++] = 0xD0;
    // mov rdx, r8
    out[n++] = 0x4C; out[n++] = 0x89; out[n++] = 0xC2;
    // mov r8, r9
    out[n++] = 0x4D; out[n++] = 0x89; out[n++] = 0xC8;
    // mov r9, [rsp+0x28]
    out[n++] = 0x4C; out[n++] = 0x8B; out[n++] = 0x4C;
    out[n++] = 0x24; out[n++] = 0x28;
    // vmcall
    out[n++] = 0x0F; out[n++] = 0x01; out[n++] = 0xC1;
    // ret
    out[n++] = 0xC3;

    // fall_through: 14 bytes of saved original prologue
    CopyMem(&out[n], saved_prologue, NTOS_PATCH_OVERWRITE_BYTES);
    n += NTOS_PATCH_OVERWRITE_BYTES;

    // mov rax, NtCreateProfile + 14
    out[n++] = 0x48; out[n++] = 0xB8;
    UINT64 resume_va = nt_create_profile_va + NTOS_PATCH_OVERWRITE_BYTES;
    CopyMem(&out[n], &resume_va, 8); n += 8;
    // jmp rax
    out[n++] = 0xFF; out[n++] = 0xE0;

    return n;
}

/*
 * Build the inline patch bytes (mov rax, trampoline_va; jmp rax).
 * Must be exactly NTOS_PATCH_OVERWRITE_BYTES (14).
 */
VOID
NtosBuildInlinePatch(
    OUT UINT8  out[NTOS_PATCH_OVERWRITE_BYTES],
    IN  UINT64 trampoline_va
    )
{
    out[0] = 0x48; out[1] = 0xB8;       // mov rax, imm64
    CopyMem(&out[2], &trampoline_va, 8);
    out[10] = 0xFF; out[11] = 0xE0;     // jmp rax
    // Pad final 2 bytes with NOP (90) so debuggers don't choke on partial
    // disassembly during the brief installation window.
    out[12] = 0x90; out[13] = 0x90;
}

/*
 * Top-level driver: allocate trampoline page, build trampoline, then call the
 * caller-supplied page-write helper to atomically overwrite NtCreateProfile's
 * first 14 bytes.
 *
 * The page-write helper is supplied because writing to ntos.text requires:
 *   - clear CR0.WP (or use EPT-redirected writable shadow)
 *   - the actual write
 *   - restore CR0.WP
 * In Phase 4 this is done by the VMM in VMX-root context. For now the helper
 * is a function pointer the integrator wires in.
 */
typedef VOID (*ntos_page_write_fn_t)(UINT64 dest_va, CONST UINT8 *bytes, UINTN len);

EFI_STATUS
NtosInstallPatch(
    IN  UINT64                nt_create_profile_va,
    OUT UINT64               *out_trampoline_va,
    IN  ntos_page_write_fn_t  page_write
    )
{
    if (!out_trampoline_va || !page_write) return EFI_INVALID_PARAMETER;

    // Capture saved prologue.
    UINT8 saved_prologue[NTOS_PATCH_OVERWRITE_BYTES];
    CopyMem(saved_prologue, (VOID *)(UINTN)nt_create_profile_va,
            NTOS_PATCH_OVERWRITE_BYTES);

    // Allocate trampoline page (one 4KB page = plenty for 64-byte trampoline).
    UINT8 *tramp = (UINT8 *)EfiAllocateRuntimePages(1);
    if (!tramp) {
        Print(L"[NtosPatch] trampoline alloc failed\n");
        return EFI_OUT_OF_RESOURCES;
    }

    UINTN tramp_size = NtosBuildTrampoline(tramp, nt_create_profile_va,
                                           saved_prologue);
    Print(L"[NtosPatch] trampoline @ %p (%u bytes)\n", tramp, (UINT32)tramp_size);

    // Build inline patch.
    UINT8 patch[NTOS_PATCH_OVERWRITE_BYTES];
    NtosBuildInlinePatch(patch, (UINT64)(UINTN)tramp);

    // Write patch via supplied helper.
    page_write(nt_create_profile_va, patch, NTOS_PATCH_OVERWRITE_BYTES);

    *out_trampoline_va = (UINT64)(UINTN)tramp;
    Print(L"[NtosPatch] installed: NtCreateProfile @ 0x%llx -> trampoline @ 0x%llx\n",
          nt_create_profile_va, (UINT64)(UINTN)tramp);
    return EFI_SUCCESS;
}

/*
 * Diagnostic: verify the inline patch is still in place. VMM polls this
 * post-install to detect any external rollback.
 */
BOOLEAN
NtosVerifyPatch(
    IN UINT64 nt_create_profile_va,
    IN UINT64 trampoline_va
    )
{
    UINT8 expected[NTOS_PATCH_OVERWRITE_BYTES];
    NtosBuildInlinePatch(expected, trampoline_va);

    UINT8 actual[NTOS_PATCH_OVERWRITE_BYTES];
    CopyMem(actual, (VOID *)(UINTN)nt_create_profile_va,
            NTOS_PATCH_OVERWRITE_BYTES);

    return CompareMem(expected, actual, NTOS_PATCH_OVERWRITE_BYTES) == 0;
}
