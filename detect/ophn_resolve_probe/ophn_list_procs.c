// ophn_list_procs.c - Phase 6j+6k: enumerate target processes via VMCALL,
// then resolve one by PID and verify session cached target_cr3 (LIST_MODULES
// works after RESOLVE_TARGET_BY_PID).
//
// Compile: cl /O2 /nologo ophn_list_procs.c /Fe:ophn_list_procs.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define OP_REGISTER             0x01
#define OP_UNREGISTER           0x05
#define OP_LIST_MODULES         0x07
#define OP_LIST_PROCESSES       0x09
#define OP_RESOLVE_TARGET_BY_PID 0x0A
#define MAGIC_HANDLE      ((HANDLE)0xCAFEDEADBEEF1234ULL)
#define MAX_P             64
#define MOD_MAX           32

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PfnNtCreateCrossVmEvent)(HANDLE, PVOID, ULONG, PVOID, ULONG);

#pragma pack(push, 1)
typedef struct { uint8_t image_sha256[32]; uint64_t image_base; uint32_t image_size; uint32_t reserved; } reg_req_t;
typedef struct { uint64_t session_key; uint32_t version; uint32_t status; } reg_resp_t;
typedef struct { reg_req_t req; reg_resp_t resp; } reg_combo_t;
#pragma pack(pop)

typedef struct {
    uint32_t pid;
    uint32_t reserved0;
    uint64_t image_base;
    uint32_t image_size;
    char     name[16];
    uint32_t reserved1;
} proc_entry_t;
typedef struct { uint32_t reserved; uint32_t reserved2; } lp_req_t;
typedef struct { uint32_t count; uint32_t status; proc_entry_t entries[MAX_P]; } lp_resp_t;
typedef struct { lp_req_t req; lp_resp_t resp; } lp_combo_t;

typedef struct { uint32_t target_pid; uint32_t reserved; } rpid_req_t;
typedef struct {
    uint32_t target_pid;
    uint32_t image_size;
    uint64_t image_base;
    uint32_t status;
    uint32_t reserved;
} resolve_resp_t;
typedef struct { rpid_req_t req; resolve_resp_t resp; } rpid_combo_t;

typedef struct { char name[64]; uint64_t dll_base; uint32_t image_size; uint32_t reserved; } mod_entry_t;
typedef struct { uint32_t pid; uint32_t reserved; } lm_req_t;
typedef struct { uint32_t count; uint32_t status; mod_entry_t modules[MOD_MAX]; } lm_resp_t;
typedef struct { lm_req_t req; lm_resp_t resp; } lm_combo_t;

int main(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PfnNtCreateCrossVmEvent fn = (PfnNtCreateCrossVmEvent)GetProcAddress(ntdll, "NtCreateCrossVmEvent");
    if (!fn) return 1;

    // Phase 5f: REGISTER walks caller .text via image_base. Must be valid.
    HMODULE self = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((uint8_t *)self + dos->e_lfanew);

    reg_combo_t reg = {0};
    reg.req.image_base = (uint64_t)(uintptr_t)self;
    reg.req.image_size = nt->OptionalHeader.SizeOfImage;
    if (fn(MAGIC_HANDLE, NULL, OP_REGISTER, &reg, sizeof(reg)) != 0 || reg.resp.status != 0) {
        printf("REGISTER failed status=%u\n", reg.resp.status); return 2;
    }
    uint64_t key = reg.resp.session_key;

    static lp_combo_t lc;
    memset(&lc, 0, sizeof(lc));
    NTSTATUS s = fn(MAGIC_HANDLE, (PVOID)key, OP_LIST_PROCESSES, &lc, sizeof(lc));
    printf("LIST_PROCESSES NTSTATUS=0x%lx status=0x%x count=%u\n",
           s, lc.resp.status, lc.resp.count);

    // Find explorer.exe in list.
    uint32_t explorer_pid = 0;
    for (unsigned i = 0; i < lc.resp.count; i++) {
        if (strncmp(lc.resp.entries[i].name, "explorer.exe", 12) == 0) {
            explorer_pid = lc.resp.entries[i].pid;
            break;
        }
    }
    if (explorer_pid == 0) {
        printf("explorer.exe not in list\n");
        fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
        return 3;
    }
    printf("found explorer.exe pid=%u\n", explorer_pid);

    // Resolve by PID.
    rpid_combo_t rc = {0};
    rc.req.target_pid = explorer_pid;
    s = fn(MAGIC_HANDLE, (PVOID)key, OP_RESOLVE_TARGET_BY_PID, &rc, sizeof(rc));
    printf("RESOLVE_BY_PID NTSTATUS=0x%lx status=0x%x pid=%u image_base=0x%llx\n",
           s, rc.resp.status, rc.resp.target_pid,
           (unsigned long long)rc.resp.image_base);
    if (rc.resp.status != 0) {
        fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
        return 4;
    }

    // Verify session cached target_cr3 by calling LIST_MODULES.
    static lm_combo_t lm;
    memset(&lm, 0, sizeof(lm));
    lm.req.pid = explorer_pid;
    s = fn(MAGIC_HANDLE, (PVOID)key, OP_LIST_MODULES, &lm, sizeof(lm));
    printf("LIST_MODULES NTSTATUS=0x%lx status=0x%x count=%u (verify target_cr3 cached)\n",
           s, lm.resp.status, lm.resp.count);
    for (unsigned i = 0; i < lm.resp.count && i < 4; i++) {
        printf("  [%u] %s\n", i, lm.resp.modules[i].name);
    }

    fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
    return 0;
}
