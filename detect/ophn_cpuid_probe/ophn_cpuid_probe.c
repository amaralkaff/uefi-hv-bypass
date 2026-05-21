// ophn_cpuid_probe.c - check Ophion VMM via magic CPUID leaf 0x4F504849
//
// VMM intercepts CPUID, when guest issues with eax='OPHI' returns:
//   eax = 'OPHN'   (0x4E48504F)
//   ebx = version  (0x00020007 = 2.7)
//   ecx = vmexit count seen so far on this core
//   edx = TSC_AUX (low 12 bits = core id from VMM perspective)
//
// On bare metal (no VMM), CPUID with eax=0x4F504849 hits the max-extended-leaf
// behavior: returns whatever the highest valid leaf returns (usually zeros or
// repeated leaf 0x80000000 response). Won't say 'OPHN'.
//
// Compile: cl /O2 ophn_cpuid_probe.c /Fe:ophn_cpuid_probe.exe
//
// Pin to BSP via: cmd /c "start /AFFINITY 1 /WAIT ophn_cpuid_probe.exe"

#include <stdio.h>
#include <stdint.h>
#include <intrin.h>
#include <Windows.h>

static void
ascii4(uint32_t v, char out[5])
{
    out[0] = (char)(v        & 0xFF);
    out[1] = (char)((v >>  8) & 0xFF);
    out[2] = (char)((v >> 16) & 0xFF);
    out[3] = (char)((v >> 24) & 0xFF);
    out[4] = 0;
}

int
main(void)
{
    int regs[4];
    char a[5], b[5], c[5], d[5];

    // Magic leaf: 'IHPO' little-endian = "OPHI" when interpreted as ASCII.
    __cpuid(regs, 0x4F504849);

    ascii4(regs[0], a);
    ascii4(regs[1], b);
    ascii4(regs[2], c);
    ascii4(regs[3], d);

    printf("CPUID(0x4F504849) =\n");
    printf("  eax = 0x%08x  '%s'\n", (unsigned)regs[0], a);
    printf("  ebx = 0x%08x  '%s'\n", (unsigned)regs[1], b);
    printf("  ecx = 0x%08x  '%s'\n", (unsigned)regs[2], c);
    printf("  edx = 0x%08x  '%s'\n", (unsigned)regs[3], d);
    printf("\n");

    if ((unsigned)regs[0] == 0x4E48504Fu) {
        unsigned ver = (unsigned)regs[1];
        unsigned major = (ver >> 16) & 0xFFFF;
        unsigned minor = ver & 0xFFFF;
        printf("OPHION VMM PRESENT — version %u.%u, exits seen=%u, core_id_msr=%u\n",
               major, minor, (unsigned)regs[2], (unsigned)regs[3] & 0xFFF);
        return 0;
    }

    printf("OPHION VMM not detected on this core (no magic 'OPHN' in eax)\n");
    printf("Run pinned to BSP: cmd /c \"start /AFFINITY 1 /WAIT ophn_cpuid_probe.exe\"\n");
    return 1;
}
