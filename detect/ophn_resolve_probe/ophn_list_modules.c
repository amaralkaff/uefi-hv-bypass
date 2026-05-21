// ophn_list_modules.c - Phase 6b: walk target process PEB->Ldr modules.
//
// Calls RESOLVE_TARGET (cache target_cr3) then LIST_MODULES.
//
// Compile: cl /O2 /nologo ophn_list_modules.c /Fe:ophn_list_modules.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define OP_REGISTER         0x01
#define OP_RESOLVE_TARGET   0x02
#define OP_UNREGISTER       0x05
#define OP_LIST_MODULES     0x07
#define MAGIC_HANDLE        ((HANDLE)0xCAFEDEADBEEF1234ULL)
#define MOD_MAX             32

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PfnNtCreateCrossVmEvent)(HANDLE, PVOID, ULONG, PVOID, ULONG);

#pragma pack(push, 1)
typedef struct { uint8_t image_sha256[32]; uint64_t image_base; uint32_t image_size; uint32_t reserved; } reg_req_t;
typedef struct { uint64_t session_key; uint32_t version; uint32_t status; } reg_resp_t;
typedef struct { reg_req_t req; reg_resp_t resp; } reg_combo_t;
#pragma pack(pop)

typedef struct { char target_name[16]; } resolve_req_t;
typedef struct { uint32_t pid; uint32_t image_size; uint64_t image_base; uint32_t status; uint32_t reserved; } resolve_resp_t;
typedef struct { resolve_req_t req; resolve_resp_t resp; } resolve_combo_t;

typedef struct { char name[64]; uint64_t dll_base; uint32_t image_size; uint32_t reserved; } mod_entry_t;
typedef struct { uint32_t pid; uint32_t reserved; } lm_req_t;
typedef struct { uint32_t count; uint32_t status; mod_entry_t modules[MOD_MAX]; } lm_resp_t;
typedef struct { lm_req_t req; lm_resp_t resp; } lm_combo_t;

int main(int argc, char **argv) {
    DWORD core = GetCurrentProcessorNumber();
    printf("core=%u\n", (unsigned)core);
    const char *target = (argc > 1) ? argv[1] : "explorer.exe";

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PfnNtCreateCrossVmEvent fn = (PfnNtCreateCrossVmEvent)GetProcAddress(ntdll, "NtCreateCrossVmEvent");
    if (!fn) return 1;

    reg_combo_t reg = {0};
    HMODULE self = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((uint8_t *)self + dos->e_lfanew);
    reg.req.image_base = (uint64_t)(uintptr_t)self;
    reg.req.image_size = nt->OptionalHeader.SizeOfImage;
    if (fn(MAGIC_HANDLE, NULL, OP_REGISTER, &reg, sizeof(reg)) != 0 || reg.resp.status != 0) {
        printf("REGISTER failed status=%u\n", reg.resp.status); return 2;
    }
    uint64_t key = reg.resp.session_key;

    resolve_combo_t rc = {0};
    strncpy_s(rc.req.target_name, sizeof(rc.req.target_name), target, sizeof(rc.req.target_name) - 1);
    if (fn(MAGIC_HANDLE, (PVOID)key, OP_RESOLVE_TARGET, &rc, sizeof(rc)) != 0 || rc.resp.status != 0) {
        printf("RESOLVE_TARGET failed status=0x%x\n", rc.resp.status);
        fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
        return 3;
    }
    printf("[+] %s pid=%u image_base=0x%llx\n", target, rc.resp.pid, (unsigned long long)rc.resp.image_base);

    static lm_combo_t lc;
    memset(&lc, 0, sizeof(lc));
    lc.req.pid = rc.resp.pid;

    NTSTATUS s = fn(MAGIC_HANDLE, (PVOID)key, OP_LIST_MODULES, &lc, sizeof(lc));
    printf("[*] LIST_MODULES NTSTATUS=0x%lx, resp.status=0x%x, count=%u\n", s, lc.resp.status, lc.resp.count);

    for (unsigned i = 0; i < lc.resp.count && i < MOD_MAX; i++) {
        printf("    [%2u] base=0x%016llx size=0x%08x  %s\n", i,
               (unsigned long long)lc.resp.modules[i].dll_base,
               lc.resp.modules[i].image_size,
               lc.resp.modules[i].name);
    }

    fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
    return lc.resp.status;
}
