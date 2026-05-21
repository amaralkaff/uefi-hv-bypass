// ophn_vmcall_test.c - Phase 4f: end-to-end VMCALL roundtrip via patched
// NtCreateCrossVmEvent → trampoline → VMCALL → VmcallDispatch → status reply.
//
// Test sequence:
//   1. REGISTER (rax=0 NULL key, rdx=session_key_ignored, r8=OP_REGISTER,
//      r9=&reg_combo, [rsp+0x28]=sizeof(reg_combo))
//   2. STATUS_QUERY using key returned from REGISTER.
//   3. UNREGISTER to clean up session table slot.
//
// Compile: cl /O2 /nologo ophn_vmcall_test.c /Fe:ophn_vmcall_test.exe
//
// Pin to BSP via cmd /c "start `"`" /B /WAIT /AFFINITY 0x1 ophn_vmcall_test.exe"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAGIC_HANDLE        ((HANDLE)0xCAFEDEADBEEF1234ULL)
#define OP_REGISTER         0x01
#define OP_RESOLVE_TARGET   0x02
#define OP_READ_MANY        0x03
#define OP_STATUS_QUERY     0x04
#define OP_UNREGISTER       0x05

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PfnNtCreateCrossVmEvent)(
    HANDLE   arg1,
    PVOID    arg2,
    ULONG    arg3,
    PVOID    arg4,
    ULONG    arg5
);

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

typedef struct {
    uint32_t ophion_loaded;
    uint32_t ophion_version;
    uint32_t patch_applied;
    uint32_t ntos_build_known;
    uint64_t vmm_uptime_ms;
} ophion_status_resp_t;
#pragma pack(pop)

int main(void) {
    DWORD core = GetCurrentProcessorNumber();
    printf("core=%u\n", (unsigned)core);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { printf("[!] no ntdll\n"); return 1; }

    PfnNtCreateCrossVmEvent fn = (PfnNtCreateCrossVmEvent)
        GetProcAddress(ntdll, "NtCreateCrossVmEvent");
    if (!fn) { printf("[!] NtCreateCrossVmEvent not exported\n"); return 1; }
    printf("[+] NtCreateCrossVmEvent stub @ %p\n", fn);

    // ------------------------------------------------------------------
    // Step 1: REGISTER. session_key (rax) = 0; rdx = NULL (caller supplies
    // junk); op = REGISTER; buf = &reg_combo with cleared image fields
    // (Phase 4 stub doesn't validate hash yet); size = sizeof(combo).
    // ------------------------------------------------------------------
    reg_combo_t reg = {0};
    HMODULE self = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((uint8_t *)self + dos->e_lfanew);
    reg.req.image_base = (uint64_t)(uintptr_t)self;
    reg.req.image_size = nt->OptionalHeader.SizeOfImage;

    printf("\n[REG] calling syscall (MAGIC, 0, OP_REGISTER, &combo, %u)...\n",
           (unsigned)sizeof(reg));
    NTSTATUS s1 = fn(MAGIC_HANDLE, NULL, OP_REGISTER, &reg, sizeof(reg));
    printf("[REG] returned NTSTATUS=0x%lx\n", s1);
    printf("      resp.status         = 0x%x  (0 = OK)\n", reg.resp.status);
    printf("      resp.ophion_version = 0x%x\n", reg.resp.ophion_version);
    printf("      resp.session_key    = 0x%llx\n",
           (unsigned long long)reg.resp.session_key);

    if (s1 != 0 || reg.resp.status != 0) {
        printf("[!] REGISTER failed; aborting\n");
        return 2;
    }

    uint64_t key = reg.resp.session_key;

    // ------------------------------------------------------------------
    // Step 2: STATUS_QUERY using returned session key.
    // ------------------------------------------------------------------
    ophion_status_resp_t st = {0};

    printf("\n[STATUS] calling syscall (MAGIC, key=0x%llx, OP_STATUS_QUERY, &st, %u)...\n",
           (unsigned long long)key, (unsigned)sizeof(st));
    NTSTATUS s2 = fn(MAGIC_HANDLE, (PVOID)key, OP_STATUS_QUERY, &st, sizeof(st));
    printf("[STATUS] returned NTSTATUS=0x%lx\n", s2);
    printf("         loaded     = %u\n", st.ophion_loaded);
    printf("         version    = 0x%x\n", st.ophion_version);
    printf("         patch_applied      = %u\n", st.patch_applied);
    printf("         ntos_build_known   = %u\n", st.ntos_build_known);
    printf("         vmm_uptime_ms      = %llu\n", (unsigned long long)st.vmm_uptime_ms);

    // ------------------------------------------------------------------
    // Step 3: UNREGISTER (free session slot).
    // ------------------------------------------------------------------
    printf("\n[UNREG] calling syscall (MAGIC, key, OP_UNREGISTER, NULL, 0)...\n");
    NTSTATUS s3 = fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
    printf("[UNREG] returned NTSTATUS=0x%lx\n", s3);

    return 0;
}
