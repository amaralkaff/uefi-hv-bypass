// ophn_resolve_set.c - resolve NtCreateProfile RVA in ntoskrnl, push to VMM.
//
// Resolution strategy (in order):
//   1. argv[1] = explicit RVA (skip everything)
//   2. Manual PE export parser on C:\Windows\System32\ntoskrnl.exe (no deps,
//      works offline). NtCreateProfile is exported on Win10 19045.
//   3. dbghelp + symsrv (download PDB on first run, ~30 MB).
//
// Push RVA to VMM via CPUID 0x4F504853 ('OPHS') with ecx=RVA. VMM validates
// rva is in-range, computes VA, body-prologue-checks via guest read, caches.
//
// Compile: cl /O2 /nologo ophn_resolve_set.c dbghelp.lib /Fe:ophn_resolve_set.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

#define OPHION_RESOLVE_GET 0x4F504852  // 'OPHR'
#define OPHION_RESOLVE_SET 0x4F504853  // 'OPHS'

//
// Manual PE export parser. Maps ntoskrnl.exe via CreateFileMapping and walks
// IMAGE_EXPORT_DIRECTORY. Returns RVA of named export, or 0 if not found.
//
static uint32_t
resolve_via_pe_exports(const char *pe_path, const char *symbol)
{
    HANDLE f = CreateFileA(pe_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA(%s) failed: %lu\n", pe_path, GetLastError());
        return 0;
    }
    HANDLE m = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!m) { CloseHandle(f); return 0; }
    BYTE *base = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(m); CloseHandle(f); return 0; }

    uint32_t rva = 0;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto out;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto out;

    IMAGE_DATA_DIRECTORY *edd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (edd->Size == 0 || edd->VirtualAddress == 0) goto out;

    // Mapped as data file, sections aren't loaded as VAs — must walk on-disk
    // section headers to translate RVAs to file offsets.
    IMAGE_SECTION_HEADER *secs = IMAGE_FIRST_SECTION(nt);
    #define RVA2OFF(rva, out_off) do { \
        BOOL found = FALSE; \
        for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++) { \
            if ((rva) >= secs[i].VirtualAddress && \
                (rva) <  secs[i].VirtualAddress + secs[i].SizeOfRawData) { \
                (out_off) = secs[i].PointerToRawData + ((rva) - secs[i].VirtualAddress); \
                found = TRUE; break; \
            } \
        } \
        if (!found) (out_off) = 0; \
    } while (0)

    DWORD edd_off = 0;
    RVA2OFF(edd->VirtualAddress, edd_off);
    if (!edd_off) goto out;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + edd_off);

    DWORD names_off = 0, ordinals_off = 0, funcs_off = 0;
    RVA2OFF(exp->AddressOfNames,        names_off);
    RVA2OFF(exp->AddressOfNameOrdinals, ordinals_off);
    RVA2OFF(exp->AddressOfFunctions,    funcs_off);
    if (!names_off || !ordinals_off || !funcs_off) goto out;

    DWORD  *names    = (DWORD  *)(base + names_off);
    WORD   *ordinals = (WORD   *)(base + ordinals_off);
    DWORD  *funcs    = (DWORD  *)(base + funcs_off);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD name_off = 0;
        RVA2OFF(names[i], name_off);
        if (!name_off) continue;
        const char *name = (const char *)(base + name_off);
        if (strcmp(name, symbol) == 0) {
            WORD ord = ordinals[i];
            if (ord < exp->NumberOfFunctions) rva = funcs[ord];
            break;
        }
    }

out:
    UnmapViewOfFile(base);
    CloseHandle(m);
    CloseHandle(f);
    return rva;
}

static uint32_t
resolve_via_dbghelp(const char *pe_path, const char *symbol)
{
    char syms_path[MAX_PATH];
    char temp_dir[MAX_PATH];
    GetTempPathA(sizeof(temp_dir), temp_dir);
    snprintf(syms_path, sizeof(syms_path),
             "srv*%sSymbols*https://msdl.microsoft.com/download/symbols",
             temp_dir);
    printf("[*] Symbol path: %s\n", syms_path);

    HANDLE proc = (HANDLE)0x4F504853;
    // No DEFERRED_LOADS — force eager PDB download on SymLoadModuleEx so
    // failures are visible immediately.
    SymSetOptions(SYMOPT_AUTO_PUBLICS | SYMOPT_UNDNAME | SYMOPT_DEBUG);
    if (!SymInitialize(proc, syms_path, FALSE)) {
        printf("[!] SymInitialize failed: %lu\n", GetLastError());
        return 0;
    }

    DWORD64 base = SymLoadModuleEx(proc, NULL, pe_path, NULL,
                                    0x10000000, 0, NULL, 0);
    if (base == 0) {
        printf("[!] SymLoadModuleEx failed: %lu\n", GetLastError());
        SymCleanup(proc);
        return 0;
    }

    SYMBOL_INFO_PACKAGE pkg = {0};
    pkg.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    pkg.si.MaxNameLen   = sizeof(pkg.name);
    uint32_t rva = 0;
    if (SymFromName(proc, symbol, &pkg.si)) {
        rva = (uint32_t)(pkg.si.Address - base);
    } else {
        printf("[!] SymFromName(%s) failed: %lu\n", symbol, GetLastError());
    }

    SymUnloadModule64(proc, base);
    SymCleanup(proc);
    return rva;
}

static int
push_rva_to_vmm(uint32_t rva)
{
    int regs[4];
    __cpuidex(regs, OPHION_RESOLVE_SET, (int)rva);
    if ((unsigned)regs[0] != OPHION_RESOLVE_SET) {
        printf("[!] OPHS leaf returned eax=0x%x, expected 0x%x — VMM not present?\n",
               (unsigned)regs[0], OPHION_RESOLVE_SET);
        return 1;
    }
    uint64_t ncp_va = ((uint64_t)(unsigned)regs[2] << 32) | (uint64_t)(unsigned)regs[1];
    unsigned flags = (unsigned)regs[3];
    printf("[+] VMM ack: NtCreateProfile = 0x%016llx, flags=0x%x\n",
           (unsigned long long)ncp_va, flags);
    printf("    NTOS=%d SVCTBL=%d NCP=%d PROL_OK=%d\n",
           !!(flags & 1), !!(flags & 2), !!(flags & 4), !!(flags & 8));
    if (!(flags & 8)) {
        printf("[!] Prologue check failed — RVA wrong or page not resident.\n");
        return 1;
    }
    return 0;
}

int
main(int argc, char **argv)
{
    DWORD core = GetCurrentProcessorNumber();
    printf("GetCurrentProcessorNumber = %u\n", (unsigned)core);

    int probe[4];
    __cpuidex(probe, OPHION_RESOLVE_GET, 0);
    if ((unsigned)probe[0] != 0x4F504852u) {
        printf("[!] VMM not present on this core. Pin to BSP via /AFFINITY 0x1.\n");
        return 1;
    }
    uint64_t ntos_base = ((uint64_t)(unsigned)probe[2] << 32) | (uint64_t)(unsigned)probe[1];
    uint32_t ntos_size = (unsigned)probe[3];
    printf("[+] VMM reports ntos_base=0x%016llx ntos_size=0x%x\n",
           (unsigned long long)ntos_base, ntos_size);

    const char *kpath = "C:\\Windows\\System32\\ntoskrnl.exe";
    uint32_t rva = 0;

    if (argc > 1) {
        rva = (uint32_t)strtoul(argv[1], NULL, 0);
        printf("[+] Using user-supplied RVA = 0x%x\n", rva);
    }

    if (rva == 0) {
        printf("[*] Resolution path 1: PE export table\n");
        rva = resolve_via_pe_exports(kpath, "NtCreateProfile");
        if (rva) {
            printf("[+] PE export NtCreateProfile RVA = 0x%x\n", rva);
        } else {
            printf("[*] NtCreateProfile not in export table.\n");
        }
    }

    if (rva == 0) {
        printf("[*] Resolution path 2: dbghelp + symsrv\n");
        rva = resolve_via_dbghelp(kpath, "NtCreateProfile");
        if (rva) printf("[+] PDB NtCreateProfile RVA = 0x%x\n", rva);
    }

    if (rva == 0) {
        printf("[!] All resolution paths failed. Find RVA via WinDbg/IDA and re-run with arg.\n");
        return 1;
    }
    if (rva >= ntos_size) {
        printf("[!] RVA 0x%x out of range (ntos_size 0x%x)\n", rva, ntos_size);
        return 1;
    }

    if (push_rva_to_vmm(rva) != 0) return 1;

    // Phase 4b: read trampoline state subleaves 8/9/10.
    int s8[4], s9[4], s10[4];
    __cpuidex(s8,  OPHION_RESOLVE_GET, 8);
    __cpuidex(s9,  OPHION_RESOLVE_GET, 9);
    __cpuidex(s10, OPHION_RESOLVE_GET, 10);

    uint64_t tramp_va = ((uint64_t)(unsigned)s8[2] << 32) | (uint64_t)(unsigned)s8[1];
    uint32_t tramp_size = (unsigned)s8[3] & 0xFFFF;
    int     tramp_built = (((unsigned)s8[3] >> 31) & 1);

    printf("\n--- trampoline state ---\n");
    printf("trampoline_va    = 0x%016llx\n", (unsigned long long)tramp_va);
    printf("trampoline_size  = %u bytes\n", tramp_size);
    printf("trampoline_built = %d\n", tramp_built);
    printf("first 12 bytes   = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           (unsigned char)(s9[1] & 0xFF), (unsigned char)((s9[1] >> 8) & 0xFF),
           (unsigned char)((s9[1] >> 16) & 0xFF), (unsigned char)((s9[1] >> 24) & 0xFF),
           (unsigned char)(s9[2] & 0xFF), (unsigned char)((s9[2] >> 8) & 0xFF),
           (unsigned char)((s9[2] >> 16) & 0xFF), (unsigned char)((s9[2] >> 24) & 0xFF),
           (unsigned char)(s9[3] & 0xFF), (unsigned char)((s9[3] >> 8) & 0xFF),
           (unsigned char)((s9[3] >> 16) & 0xFF), (unsigned char)((s9[3] >> 24) & 0xFF));
    printf("saved prologue   = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           (unsigned char)(s10[1] & 0xFF), (unsigned char)((s10[1] >> 8) & 0xFF),
           (unsigned char)((s10[1] >> 16) & 0xFF), (unsigned char)((s10[1] >> 24) & 0xFF),
           (unsigned char)(s10[2] & 0xFF), (unsigned char)((s10[2] >> 8) & 0xFF),
           (unsigned char)((s10[2] >> 16) & 0xFF), (unsigned char)((s10[2] >> 24) & 0xFF),
           (unsigned char)(s10[3] & 0xFF), (unsigned char)((s10[3] >> 8) & 0xFF),
           (unsigned char)((s10[3] >> 16) & 0xFF), (unsigned char)((s10[3] >> 24) & 0xFF));
    return 0;
}
