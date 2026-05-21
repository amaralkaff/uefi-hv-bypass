// ophn_stealth_test.c - Phase 7a: verify magic CPUID lockdown.
//
// Sequence:
//   1. probe OPHI (0x4F504849) — should return 'OPHN' identity.
//   2. trigger lockdown via OPHX subleaf 0xFD.
//   3. probe OPHI again — should now return bare CPUID values (not 'OPHN').
//   4. probe OPHR/OPHS/OPHX too — all silent post-lockdown.
//
// Compile: cl /O2 /nologo ophn_stealth_test.c /Fe:ophn_stealth_test.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <intrin.h>

#define OPHI 0x4F504849
#define OPHR 0x4F504852
#define OPHS 0x4F504853
#define OPHX 0x4F504858

static void
probe(unsigned leaf, unsigned sub, const char *label)
{
    int regs[4];
    __cpuidex(regs, (int)leaf, (int)sub);
    printf("%-30s eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x\n",
           label,
           (unsigned)regs[0], (unsigned)regs[1],
           (unsigned)regs[2], (unsigned)regs[3]);
}

int main(void) {
    DWORD core = GetCurrentProcessorNumber();
    printf("core=%u\n\n", (unsigned)core);

    printf("=== BEFORE lockdown ===\n");
    probe(OPHI, 0, "OPHI sub=0");
    probe(OPHR, 0, "OPHR sub=0 (ntos_base)");
    probe(OPHX, 0, "OPHX sub=0 (install state)");
    printf("\n");

    printf("=== triggering OPHX sub=0xFD lockdown ===\n");
    probe(OPHX, 0xFD, "OPHX sub=0xFD (lock)");
    printf("\n");

    printf("=== AFTER lockdown ===\n");
    probe(OPHI, 0, "OPHI sub=0");
    probe(OPHR, 0, "OPHR sub=0");
    probe(OPHS, 0, "OPHS sub=0");
    probe(OPHX, 0, "OPHX sub=0");

    int after_ophi[4];
    __cpuidex(after_ophi, OPHI, 0);
    int leaked = ((unsigned)after_ophi[0] == 0x4E48504Fu);  // 'OPHN'
    printf("\nstealth status: %s\n",
           leaked ? "LEAKED — OPHI still returns 'OPHN'" : "PASS — VMM hidden");
    return leaked ? 1 : 0;
}
