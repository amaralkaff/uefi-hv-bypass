// ophn_install_cloak.c - Phase 7d cloaked installer. Triggers VMM-side
// ntos.text patch via CPUID 0x4F504858 'OPHX' subleaf 0xFE.
//
// Difference from ophn_install (subleaf 0xFF):
//   0xFF = direct write to ntos.text (Phase 4d-i, breaks under PG)
//   0xFE = patch alt page only + EPT cloak install (Phase 7d, survives PG)
//
// PRECONDITION: ophn_resolve_set + push_offsets must have run first.
//
// Status codes (via subleaf 0x80 readback, ebx):
//   0 ok                         5 PT walk failed
//   1 no trampoline              6 cross-page (NCP straddles 4KB)
//   2 no NCP target              7 EPT cloak install failed
//   3 prologue mismatch
//   4 alt page alloc failed
//
// Compile: cl /O2 /nologo ophn_install_cloak.c /Fe:ophn_install_cloak.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <intrin.h>
#include <string.h>

#define OPHX_LEAF 0x4F504858

int
main(int argc, char **argv)
{
    // Pin to BSP (only core under VMM per Phase 3 partial).
    SetProcessAffinityMask(GetCurrentProcess(), 1);
    Sleep(50);
    DWORD core = GetCurrentProcessorNumber();
    printf("BSP affinity, current core = %u\n", (unsigned)core);

    int probe[4];
    __cpuidex(probe, OPHX_LEAF, 0);
    if ((unsigned)probe[0] != OPHX_LEAF) {
        printf("[!] OPHX leaf absent. Stealth lockdown active or VMM down.\n");
        return 1;
    }

    int do_install = (argc > 1 && strcmp(argv[1], "--install") == 0);

    if (do_install) {
        printf("[*] Triggering cloaked install (subleaf 0xFE)...\n");
        int s[4];
        __cpuidex(s, OPHX_LEAF, 0xFE);
        // Subleaf 0xFE auto-falls-through to subleaf 0x80 readback in VMM.
        printf("[*] cloak install status = %u (0=ok)\n", (unsigned)s[1]);
    }

    int s0[4], s1[4];
    __cpuidex(s0, OPHX_LEAF, 0x80);  // status + attempted
    __cpuidex(s1, OPHX_LEAF, 0x81);  // target_gphys + alt_pfn

    printf("\n--- 7d cloak state ---\n");
    printf("status        = %u (0=ok 1=no-tramp 2=no-ncp 3=prol 4=alloc 5=walk 6=cross 7=cloak)\n",
           (unsigned)s0[1]);
    printf("attempted     = %u\n", (unsigned)s0[2]);

    uint64_t target_gphys = ((uint64_t)(unsigned)s1[2] << 32) | (unsigned)s1[1];
    printf("target_gphys  = 0x%016llx\n", (unsigned long long)target_gphys);
    printf("alt_pfn       = 0x%08x (alt_phys = 0x%llx)\n",
           (unsigned)s1[3], ((unsigned long long)(unsigned)s1[3]) << 12);

    return (unsigned)s0[1] == 0 ? 0 : 1;
}
