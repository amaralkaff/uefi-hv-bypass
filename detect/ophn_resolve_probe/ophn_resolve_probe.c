// ophn_resolve_probe.c - read Phase 4a magic CPUID leaf 0x4F504852 ('OPHR')
//
// VMM caches ntoskrnl base + KiServiceTable + NtCreateProfile after first
// call. Returns via 5 subleaves (rcx=0..4):
//   0: ntos_base (rbx:rcx), ntos_size (rdx)
//   1: NtCreateProfile (rbx:rcx), flags (rdx)
//   2: KiServiceTable (rbx:rcx), LSTAR low (rdx)
//   3: guest_cr3 (rbx:rcx), LSTAR high (rdx)
//   4: walked_pages (rbx), resolved (rcx), flags (rdx)
//
// Compile: cl /O2 ophn_resolve_probe.c
// Run pinned to BSP: cmd /c "start `"`" /B /WAIT /AFFINITY 0x1 ophn_resolve_probe.exe"

#include <stdio.h>
#include <stdint.h>
#include <intrin.h>
#include <Windows.h>

#define MAGIC 0x4F504852

int main(void) {
    int regs[4];
    DWORD core = GetCurrentProcessorNumber();
    printf("GetCurrentProcessorNumber = %u\n", (unsigned)core);
    printf("\n--- Phase 4a CPUID resolve probe (leaf 0x%X 'OPHR') ---\n", MAGIC);

    for (int sub = 0; sub <= 7; sub++) {
        __cpuidex(regs, MAGIC, sub);
        unsigned a = regs[0], b = regs[1], c = regs[2], d = regs[3];
        printf("sub=%d : eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x\n",
               sub, a, b, c, d);
    }

    int s0[4], s1[4], s2[4], s3[4], s4[4];
    __cpuidex(s0, MAGIC, 0);
    __cpuidex(s1, MAGIC, 1);
    __cpuidex(s2, MAGIC, 2);
    __cpuidex(s3, MAGIC, 3);
    __cpuidex(s4, MAGIC, 4);

    if ((unsigned)s0[0] != 0x4F504852u) {
        printf("\nNot virtualized on this core (no OPHR ack). Pin to BSP via /AFFINITY 0x1.\n");
        return 1;
    }

    uint64_t ntos_base = ((uint64_t)(unsigned)s0[2] << 32) | (uint64_t)(unsigned)s0[1];
    uint32_t ntos_size = (unsigned)s0[3];
    uint64_t ncp_va    = ((uint64_t)(unsigned)s1[2] << 32) | (uint64_t)(unsigned)s1[1];
    uint32_t flags     = (unsigned)s1[3];
    uint64_t svctbl    = ((uint64_t)(unsigned)s2[2] << 32) | (uint64_t)(unsigned)s2[1];
    uint64_t lstar     = ((uint64_t)(unsigned)s3[3] << 32) | (uint64_t)(unsigned)s2[3];
    uint64_t cr3       = ((uint64_t)(unsigned)s3[2] << 32) | (uint64_t)(unsigned)s3[1];
    uint32_t walked    = (unsigned)s4[1];
    uint32_t resolved  = (unsigned)s4[2];

    printf("\n--- decoded ---\n");
    printf("guest_cr3       = 0x%016llx\n", (unsigned long long)cr3);
    printf("LSTAR           = 0x%016llx\n", (unsigned long long)lstar);
    printf("ntos_base       = 0x%016llx\n", (unsigned long long)ntos_base);
    printf("ntos_size       = 0x%x  (%.2f MB)\n", ntos_size, ntos_size / (1024.0 * 1024.0));
    printf("KiServiceTable  = 0x%016llx\n", (unsigned long long)svctbl);
    printf("NtCreateProfile = 0x%016llx\n", (unsigned long long)ncp_va);
    printf("flags           = 0x%08x  (NTOS=%d SVCTBL=%d NCP=%d PROL_OK=%d)\n",
           flags, !!(flags & 1), !!(flags & 2), !!(flags & 4), !!(flags & 8));
    printf("walked_pages    = %u\n", walked);
    printf("resolved        = %u\n", resolved);
    return 0;
}
