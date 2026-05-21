// ophn_install.c - Phase 4d-i installer. Triggers VMM-side ntos.text patch
// via CPUID 0x4F504858 'OPHX' (subleaf 0xFF = do install). Reads back status
// + inline_patch + post_read + pre_read for verification.
//
// PRECONDITION: ophn_resolve_set must have run first to lock NCP target VA.
//
// PATCHGUARD WARNING: This writes 14 bytes into ntos.text. PG's next
// integrity scan (typically 1-5 minutes) may BSOD with 0x109. Phase 4d-ii
// adds EPT cloak (read-shadow with original bytes) to defeat PG. Don't run
// this for extended sessions until Phase 4d-ii lands.
//
// Compile: cl /O2 /nologo ophn_install.c /Fe:ophn_install.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <intrin.h>

#define OPHX_LEAF 0x4F504858

static void
print_bytes(const char *label, unsigned b, unsigned c, unsigned d)
{
    printf("%-22s = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           label,
           (unsigned char)(b & 0xFF), (unsigned char)((b >> 8) & 0xFF),
           (unsigned char)((b >> 16) & 0xFF), (unsigned char)((b >> 24) & 0xFF),
           (unsigned char)(c & 0xFF), (unsigned char)((c >> 8) & 0xFF),
           (unsigned char)((c >> 16) & 0xFF), (unsigned char)((c >> 24) & 0xFF),
           (unsigned char)(d & 0xFF), (unsigned char)((d >> 8) & 0xFF),
           (unsigned char)((d >> 16) & 0xFF), (unsigned char)((d >> 24) & 0xFF));
}

int
main(int argc, char **argv)
{
    DWORD core = GetCurrentProcessorNumber();
    printf("GetCurrentProcessorNumber = %u\n", (unsigned)core);

    int probe[4];
    __cpuidex(probe, OPHX_LEAF, 0);
    if ((unsigned)probe[0] != OPHX_LEAF) {
        printf("[!] OPHX leaf not present. VMM not on this core?\n");
        return 1;
    }

    int do_install = (argc > 1 && strcmp(argv[1], "--install") == 0);

    if (do_install) {
        printf("[*] Triggering install (subleaf 0xFF)...\n");
        printf("[!] PatchGuard 0x109 BSOD possible within minutes.\n");
        int s[4];
        __cpuidex(s, OPHX_LEAF, 0xFF);
        printf("[*] install returned status = %u (0=ok)\n", (unsigned)s[1]);
    }

    int s0[4], s1[4], s2[4], s3[4];
    __cpuidex(s0, OPHX_LEAF, 0);
    __cpuidex(s1, OPHX_LEAF, 1);
    __cpuidex(s2, OPHX_LEAF, 2);
    __cpuidex(s3, OPHX_LEAF, 3);

    printf("\n--- install state ---\n");
    printf("status     = %u (0=ok 1=no-tramp 2=no-ncp 3=prol-mismatch 4=short-write 5=short-read 6=verify-fail)\n",
           (unsigned)s0[1]);
    printf("attempted  = %u\n", (unsigned)s0[2]);
    printf("tramp_va_l = 0x%08x\n", (unsigned)s0[3]);
    print_bytes("inline_patch (12B)",
                (unsigned)s1[1], (unsigned)s1[2], (unsigned)s1[3]);
    print_bytes("pre_read   (12B)",
                (unsigned)s3[1], (unsigned)s3[2], (unsigned)s3[3]);
    print_bytes("post_read  (12B)",
                (unsigned)s2[1], (unsigned)s2[2], (unsigned)s2[3]);

    return (unsigned)s0[1] == 0 ? 0 : 1;
}
