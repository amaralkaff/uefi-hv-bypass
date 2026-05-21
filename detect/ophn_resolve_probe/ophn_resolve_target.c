// ophn_resolve_target.c - Phase 5c: test RESOLVE_TARGET via VMCALL.
//
// Walks PsActiveProcessHead in VMX-root, matches EPROCESS.ImageFileName
// against argv[1] (NUL-padded ASCII, max 15 chars). Returns PID + image base.
//
// Default target = "explorer.exe" (always exists on interactive session).
//
// Compile: cl /O2 /nologo ophn_resolve_target.c /Fe:ophn_resolve_target.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#define OP_REGISTER         0x01
#define OP_RESOLVE_TARGET   0x02
#define OP_UNREGISTER       0x05
#define MAGIC_HANDLE        ((HANDLE)0xCAFEDEADBEEF1234ULL)

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

typedef struct {
    char target_name[16];
} ophion_resolve_req_t;
typedef struct {
    uint32_t target_pid;
    uint32_t image_size;
    uint64_t image_base;
    uint32_t status;
    uint32_t reserved;
} ophion_resolve_resp_t;
typedef struct {
    ophion_resolve_req_t  req;
    ophion_resolve_resp_t resp;
} resolve_combo_t;

int main(int argc, char **argv) {
    DWORD core = GetCurrentProcessorNumber();
    printf("core=%u\n", (unsigned)core);

    const char *target = (argc > 1) ? argv[1] : "explorer.exe";
    printf("[+] target = \"%s\"\n", target);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PfnNtCreateCrossVmEvent fn = (PfnNtCreateCrossVmEvent)
        GetProcAddress(ntdll, "NtCreateCrossVmEvent");
    if (!fn) { printf("[!] no syscall stub\n"); return 1; }

    reg_combo_t reg = {0};
    HMODULE self = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((uint8_t *)self + dos->e_lfanew);
    reg.req.image_base = (uint64_t)(uintptr_t)self;
    reg.req.image_size = nt->OptionalHeader.SizeOfImage;
    NTSTATUS s1 = fn(MAGIC_HANDLE, NULL, OP_REGISTER, &reg, sizeof(reg));
    if (s1 != 0 || reg.resp.status != 0) {
        printf("[!] REGISTER failed s=0x%lx status=0x%x\n", s1, reg.resp.status);
        return 2;
    }
    uint64_t key = reg.resp.session_key;
    printf("[+] session_key = 0x%llx\n", (unsigned long long)key);

    resolve_combo_t rc = {0};
    strncpy_s(rc.req.target_name, sizeof(rc.req.target_name),
              target, sizeof(rc.req.target_name) - 1);

    NTSTATUS s2 = fn(MAGIC_HANDLE, (PVOID)key, OP_RESOLVE_TARGET, &rc, sizeof(rc));
    printf("[*] RESOLVE_TARGET NTSTATUS=0x%lx\n", s2);
    printf("    resp.status     = 0x%x  (0=ok, 4=not_found, 1=offsets_not_set)\n",
           rc.resp.status);
    printf("    resp.target_pid = %u\n", rc.resp.target_pid);
    printf("    resp.image_base = 0x%llx\n", (unsigned long long)rc.resp.image_base);
    printf("    resp.image_size = 0x%x  (Phase 5d)\n", rc.resp.image_size);

    fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);

    // Diagnostic readback subleaves 13/14/15.
    int s13[4], s14[4], s15[4];
    __cpuidex(s13, 0x4F504852, 13);
    __cpuidex(s14, 0x4F504852, 14);
    __cpuidex(s15, 0x4F504852, 15);
    uint64_t first_link = ((uint64_t)(unsigned)s13[2] << 32) | (uint64_t)(unsigned)s13[1];
    uint32_t iter       = (unsigned)s13[3];
    uint64_t last_cr3   = ((uint64_t)(unsigned)s14[2] << 32) | (uint64_t)(unsigned)s14[1];
    uint32_t last_eproc_lo = (unsigned)s14[3];
    printf("\n=== diag (OPHR sub 13/14/15) ===\n");
    printf("head VA          = 0x%016llx (from sub12 readback if needed)\n", 0ULL);
    printf("first_link       = 0x%016llx\n", (unsigned long long)first_link);
    printf("iter             = %u\n", iter);
    printf("last_cr3         = 0x%016llx\n", (unsigned long long)last_cr3);
    printf("last_eproc_lo    = 0x%08x\n", last_eproc_lo);
    printf("last_name 12B    = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x  '%c%c%c%c%c%c%c%c%c%c%c%c'\n",
        (unsigned char)(s15[1] & 0xFF), (unsigned char)((s15[1] >> 8) & 0xFF),
        (unsigned char)((s15[1] >> 16) & 0xFF), (unsigned char)((s15[1] >> 24) & 0xFF),
        (unsigned char)(s15[2] & 0xFF), (unsigned char)((s15[2] >> 8) & 0xFF),
        (unsigned char)((s15[2] >> 16) & 0xFF), (unsigned char)((s15[2] >> 24) & 0xFF),
        (unsigned char)(s15[3] & 0xFF), (unsigned char)((s15[3] >> 8) & 0xFF),
        (unsigned char)((s15[3] >> 16) & 0xFF), (unsigned char)((s15[3] >> 24) & 0xFF),
        (s15[1]&0xFF)?(char)(s15[1]&0xFF):'.', ((s15[1]>>8)&0xFF)?(char)((s15[1]>>8)&0xFF):'.',
        ((s15[1]>>16)&0xFF)?(char)((s15[1]>>16)&0xFF):'.', ((s15[1]>>24)&0xFF)?(char)((s15[1]>>24)&0xFF):'.',
        (s15[2]&0xFF)?(char)(s15[2]&0xFF):'.', ((s15[2]>>8)&0xFF)?(char)((s15[2]>>8)&0xFF):'.',
        ((s15[2]>>16)&0xFF)?(char)((s15[2]>>16)&0xFF):'.', ((s15[2]>>24)&0xFF)?(char)((s15[2]>>24)&0xFF):'.',
        (s15[3]&0xFF)?(char)(s15[3]&0xFF):'.', ((s15[3]>>8)&0xFF)?(char)((s15[3]>>8)&0xFF):'.',
        ((s15[3]>>16)&0xFF)?(char)((s15[3]>>16)&0xFF):'.', ((s15[3]>>24)&0xFF)?(char)((s15[3]>>24)&0xFF):'.');

    return rc.resp.status;
}
