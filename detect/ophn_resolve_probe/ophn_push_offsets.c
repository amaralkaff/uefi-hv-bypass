// ophn_push_offsets.c - Phase 5b: resolve kernel symbol VAs + EPROCESS field
// offsets, push via VMCALL OP_SET_KERNEL_OFFSETS.
//
// Resolution strategy (in order):
//   1. dbghelp + symsrv (downloads ntkrnlmp.pdb on first run, ~30 MB)
//   2. cmdline override if dbghelp fails:
//        ophn_push_offsets.exe --pap-rva 0xXXXXXX
//      Other offsets default to Win10 19045 KB-stable values; override with
//      --aplinks --upid --image --dtb --secbase --peb if needed.
//
// Compile: cl /O2 /nologo ophn_push_offsets.c dbghelp.lib /Fe:ophn_push_offsets.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <intrin.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

#define OPHION_RESOLVE_GET 0x4F504852

#define OP_REGISTER             0x01
#define OP_STATUS_QUERY         0x04
#define OP_UNREGISTER           0x05
#define OP_SET_KERNEL_OFFSETS   0x06

#define MAGIC_HANDLE  ((HANDLE)0xCAFEDEADBEEF1234ULL)

// Win10 19045 EPROCESS field offsets — stable across LCUs for this build.
// Override via cmdline if Windows updates change them.
#define DEFAULT_OFF_ACTIVE_PROCESS_LINKS  0x448
#define DEFAULT_OFF_UNIQUE_PROCESS_ID     0x440
#define DEFAULT_OFF_IMAGE_FILE_NAME       0x5A8
#define DEFAULT_OFF_DIRECTORY_TABLE_BASE  0x028
#define DEFAULT_OFF_SECTION_BASE_ADDRESS  0x520
#define DEFAULT_OFF_PEB                   0x550

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PfnNtCreateCrossVmEvent)(HANDLE, PVOID, ULONG, PVOID, ULONG);

#pragma pack(push, 1)
typedef struct {
    uint8_t  image_sha256[32];
    uint64_t image_base;
    uint32_t image_size;
    uint32_t reserved;
} ophion_register_req_t;

typedef struct {
    uint64_t session_key;
    uint32_t ophion_version;
    uint32_t status;
} ophion_register_resp_t;

typedef struct {
    ophion_register_req_t  req;
    ophion_register_resp_t resp;
} reg_combo_t;
#pragma pack(pop)

// Kernel offsets struct: NOT packed — matches VMM-side default alignment
// (uint64_t leader rounds total to 32). With pack(1) sizeof=28, VMM
// rejects with INVALID_ARG because sizeof(ophion_kernel_offsets_t)=32.
typedef struct {
    uint64_t ps_active_process_head_va;
    uint16_t off_active_process_links;
    uint16_t off_unique_process_id;
    uint16_t off_image_file_name;
    uint16_t off_directory_table_base;
    uint16_t off_section_base_address;
    uint16_t off_peb;
    uint32_t status;
    uint32_t reserved;
} ophion_kernel_offsets_t;

static BOOL CALLBACK
sym_callback(HANDLE proc, ULONG ActionCode, ULONG64 CallbackData, ULONG64 UserContext)
{
    (void)proc; (void)UserContext;
    if (ActionCode == CBA_DEBUG_INFO) {
        fputs("[dbghelp] ", stdout);
        fputs((const char *)CallbackData, stdout);
    }
    return FALSE;
}

static int
get_live_ntos(uint64_t *out_base, uint32_t *out_size)
{
    int probe[4];
    __cpuidex(probe, OPHION_RESOLVE_GET, 0);
    if ((unsigned)probe[0] != 0x4F504852u) return 1;
    *out_base = ((uint64_t)(unsigned)probe[2] << 32) | (uint64_t)(unsigned)probe[1];
    *out_size = (unsigned)probe[3];
    return 0;
}

static int
resolve_via_dbghelp(uint64_t *out_pap_rva, ophion_kernel_offsets_t *out)
{
    char syms[MAX_PATH];
    char temp_dir[MAX_PATH];
    GetTempPathA(sizeof(temp_dir), temp_dir);
    snprintf(syms, sizeof(syms),
             "srv*%sSymbols*https://msdl.microsoft.com/download/symbols", temp_dir);

    SetEnvironmentVariableA("_NT_SYMBOL_PATH", syms);

    HANDLE proc = (HANDLE)0x4F504853;
    SymSetOptions(SYMOPT_DEBUG | SYMOPT_AUTO_PUBLICS | SYMOPT_UNDNAME);

    if (!SymInitialize(proc, syms, FALSE)) {
        printf("[!] SymInitialize failed: %lu\n", GetLastError());
        return 1;
    }
    SymRegisterCallback64(proc, sym_callback, 0);

    DWORD64 base = SymLoadModuleEx(proc, NULL,
        "C:\\Windows\\System32\\ntoskrnl.exe", NULL, 0x10000000, 0, NULL, 0);
    if (base == 0) {
        printf("[!] SymLoadModuleEx failed: %lu\n", GetLastError());
        SymCleanup(proc);
        return 1;
    }

    SYMBOL_INFO_PACKAGE pkg = {0};
    pkg.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    pkg.si.MaxNameLen   = sizeof(pkg.name);
    if (!SymFromName(proc, "PsActiveProcessHead", &pkg.si)) {
        printf("[!] SymFromName(PsActiveProcessHead) failed: %lu\n", GetLastError());
        SymCleanup(proc);
        return 1;
    }
    *out_pap_rva = pkg.si.Address - base;

    // EPROCESS field offsets via type info.
    SYMBOL_INFO_PACKAGE eproc = {0};
    eproc.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    eproc.si.MaxNameLen   = sizeof(eproc.name);
    if (!SymGetTypeFromName(proc, base, "_EPROCESS", &eproc.si)) {
        printf("[!] SymGetTypeFromName(_EPROCESS) failed: %lu\n", GetLastError());
        SymCleanup(proc);
        return 1;
    }
    ULONG eproc_typeid = eproc.si.TypeIndex;
    DWORD child_count = 0;
    SymGetTypeInfo(proc, base, eproc_typeid, TI_GET_CHILDRENCOUNT, &child_count);
    TI_FINDCHILDREN_PARAMS *fc = (TI_FINDCHILDREN_PARAMS *)
        calloc(1, sizeof(TI_FINDCHILDREN_PARAMS) + child_count * sizeof(ULONG));
    fc->Count = child_count;
    SymGetTypeInfo(proc, base, eproc_typeid, TI_FINDCHILDREN, fc);

    struct { const char *name; uint16_t *target; } fields[] = {
        { "ActiveProcessLinks", &out->off_active_process_links },
        { "UniqueProcessId",    &out->off_unique_process_id },
        { "ImageFileName",      &out->off_image_file_name },
        { "DirectoryTableBase", &out->off_directory_table_base },
        { "SectionBaseAddress", &out->off_section_base_address },
        { "Peb",                &out->off_peb },
    };
    for (DWORD i = 0; i < child_count; i++) {
        WCHAR *name = NULL;
        if (!SymGetTypeInfo(proc, base, fc->ChildId[i], TI_GET_SYMNAME, &name)) continue;
        char nameA[64] = {0};
        WideCharToMultiByte(CP_UTF8, 0, name, -1, nameA, sizeof(nameA), NULL, NULL);
        LocalFree(name);
        DWORD off = 0;
        SymGetTypeInfo(proc, base, fc->ChildId[i], TI_GET_OFFSET, &off);
        for (size_t j = 0; j < sizeof(fields) / sizeof(fields[0]); j++) {
            if (strcmp(nameA, fields[j].name) == 0) *fields[j].target = (uint16_t)off;
        }
    }
    free(fc);
    SymCleanup(proc);
    return 0;
}

static int
push_via_vmcall(ophion_kernel_offsets_t *off)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PfnNtCreateCrossVmEvent fn = (PfnNtCreateCrossVmEvent)
        GetProcAddress(ntdll, "NtCreateCrossVmEvent");
    if (!fn) return 1;

    reg_combo_t reg = {0};
    HMODULE self = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((uint8_t *)self + dos->e_lfanew);
    reg.req.image_base = (uint64_t)(uintptr_t)self;
    reg.req.image_size = nt->OptionalHeader.SizeOfImage;
    NTSTATUS s1 = fn(MAGIC_HANDLE, NULL, OP_REGISTER, &reg, sizeof(reg));
    if (s1 != 0 || reg.resp.status != 0) {
        printf("[!] REGISTER failed (NTSTATUS=0x%lx, resp.status=0x%x)\n",
               s1, reg.resp.status);
        return 1;
    }
    uint64_t key = reg.resp.session_key;

    NTSTATUS s2 = fn(MAGIC_HANDLE, (PVOID)key, OP_SET_KERNEL_OFFSETS,
                    off, sizeof(*off));
    printf("[*] SET_KERNEL_OFFSETS NTSTATUS=0x%lx, resp.status=0x%x\n",
           s2, off->status);

    fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
    return (s2 == 0 && off->status == 0) ? 0 : 1;
}

static uint32_t
parse_u32(const char *s)
{
    return (uint32_t)strtoul(s, NULL, 0);
}

int main(int argc, char **argv) {
    DWORD core = GetCurrentProcessorNumber();
    printf("core=%u\n", (unsigned)core);

    uint64_t ntos_base = 0;
    uint32_t ntos_size = 0;
    if (get_live_ntos(&ntos_base, &ntos_size) != 0) {
        printf("[!] VMM not present on this core. Pin to BSP via /AFFINITY 0x1.\n");
        return 1;
    }
    printf("[+] live ntos_base=0x%016llx size=0x%x\n",
           (unsigned long long)ntos_base, ntos_size);

    ophion_kernel_offsets_t off = {0};
    off.off_active_process_links = DEFAULT_OFF_ACTIVE_PROCESS_LINKS;
    off.off_unique_process_id    = DEFAULT_OFF_UNIQUE_PROCESS_ID;
    off.off_image_file_name      = DEFAULT_OFF_IMAGE_FILE_NAME;
    off.off_directory_table_base = DEFAULT_OFF_DIRECTORY_TABLE_BASE;
    off.off_section_base_address = DEFAULT_OFF_SECTION_BASE_ADDRESS;
    off.off_peb                  = DEFAULT_OFF_PEB;

    uint64_t pap_rva = 0;
    int manual = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pap-rva") && i + 1 < argc) {
            pap_rva = strtoull(argv[++i], NULL, 0); manual = 1;
        } else if (!strcmp(argv[i], "--aplinks") && i + 1 < argc) {
            off.off_active_process_links = (uint16_t)parse_u32(argv[++i]); manual = 1;
        } else if (!strcmp(argv[i], "--upid") && i + 1 < argc) {
            off.off_unique_process_id = (uint16_t)parse_u32(argv[++i]); manual = 1;
        } else if (!strcmp(argv[i], "--image") && i + 1 < argc) {
            off.off_image_file_name = (uint16_t)parse_u32(argv[++i]); manual = 1;
        } else if (!strcmp(argv[i], "--dtb") && i + 1 < argc) {
            off.off_directory_table_base = (uint16_t)parse_u32(argv[++i]); manual = 1;
        } else if (!strcmp(argv[i], "--secbase") && i + 1 < argc) {
            off.off_section_base_address = (uint16_t)parse_u32(argv[++i]); manual = 1;
        } else if (!strcmp(argv[i], "--peb") && i + 1 < argc) {
            off.off_peb = (uint16_t)parse_u32(argv[++i]); manual = 1;
        }
    }

    if (!manual) {
        printf("[*] Trying dbghelp + symsrv...\n");
        if (resolve_via_dbghelp(&pap_rva, &off) == 0) {
            printf("[+] PsActiveProcessHead RVA=0x%llx (via PDB)\n",
                   (unsigned long long)pap_rva);
        } else {
            printf("[!] dbghelp failed.\n");
            printf("    Get RVA via WinDbg: kd> ? @@(&nt!PsActiveProcessHead) - nt\n");
            printf("    Then re-run: ophn_push_offsets.exe --pap-rva 0xRVA\n");
            return 1;
        }
    }

    if (pap_rva == 0 || pap_rva >= ntos_size) {
        printf("[!] PAP RVA 0x%llx out of range (size 0x%x)\n",
               (unsigned long long)pap_rva, ntos_size);
        return 1;
    }

    off.ps_active_process_head_va = ntos_base + pap_rva;
    printf("\n=== resolved offsets ===\n");
    printf("PsActiveProcessHead = 0x%016llx (RVA 0x%llx)\n",
           (unsigned long long)off.ps_active_process_head_va,
           (unsigned long long)pap_rva);
    printf("ActiveProcessLinks  = 0x%x\n", off.off_active_process_links);
    printf("UniqueProcessId     = 0x%x\n", off.off_unique_process_id);
    printf("ImageFileName       = 0x%x\n", off.off_image_file_name);
    printf("DirectoryTableBase  = 0x%x\n", off.off_directory_table_base);
    printf("SectionBaseAddress  = 0x%x\n", off.off_section_base_address);
    printf("Peb                 = 0x%x\n", off.off_peb);

    printf("\n[*] pushing to VMM via VMCALL...\n");
    if (push_via_vmcall(&off) != 0) return 2;

    int s12[4];
    __cpuidex(s12, OPHION_RESOLVE_GET, 12);
    uint64_t pap = ((uint64_t)(unsigned)s12[2] << 32) | (uint64_t)(unsigned)s12[1];
    unsigned packed = (unsigned)s12[3];
    int set = (packed >> 31) & 1;
    unsigned aplinks = (packed >> 16) & 0xFFFF;
    unsigned upid    = packed & 0xFFFF;

    printf("\n=== VMM readback (OPHR sub 12) ===\n");
    printf("PsActiveProcessHead = 0x%016llx\n", (unsigned long long)pap);
    printf("offsets_set         = %d\n", set);
    printf("ActiveProcessLinks  = 0x%x\n", aplinks);
    printf("UniqueProcessId     = 0x%x\n", upid);

    return set ? 0 : 3;
}

