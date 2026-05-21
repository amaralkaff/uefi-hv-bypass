// ophn_read_many.c - Phase 5d: cross-process memory read via VMCALL.
//
// Steps:
//   1. REGISTER session.
//   2. RESOLVE_TARGET argv[1] (default "explorer.exe") to lock target_cr3.
//   3. READ_MANY src_va=image_base for 16 bytes — should return PE "MZ" header.
//   4. Print bytes + verify "MZ" signature at offset 0.
//   5. UNREGISTER.
//
// Compile: cl /O2 /nologo ophn_read_many.c /Fe:ophn_read_many.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define OP_REGISTER         0x01
#define OP_RESOLVE_TARGET   0x02
#define OP_READ_MANY        0x03
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

#define READ_MAX 64
typedef struct {
    uint64_t src_va;
    uint64_t dst_va;
    uint32_t len;
    uint32_t reserved;
} ophion_read_entry_t;
typedef struct {
    uint32_t target_pid;
    uint32_t entry_count;
    ophion_read_entry_t entries[READ_MAX];
} ophion_read_many_req_t;
typedef struct {
    uint32_t bytes_read[READ_MAX];
    uint32_t status;
    uint32_t reserved;
} ophion_read_many_resp_t;
typedef struct {
    ophion_read_many_req_t  req;
    ophion_read_many_resp_t resp;
} read_combo_t;

int main(int argc, char **argv) {
    DWORD core = GetCurrentProcessorNumber();
    printf("core=%u\n", (unsigned)core);
    const char *target = (argc > 1) ? argv[1] : "explorer.exe";

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
    if (fn(MAGIC_HANDLE, NULL, OP_REGISTER, &reg, sizeof(reg)) != 0 ||
        reg.resp.status != 0) {
        printf("[!] REGISTER failed\n"); return 2;
    }
    uint64_t key = reg.resp.session_key;

    resolve_combo_t rc = {0};
    strncpy_s(rc.req.target_name, sizeof(rc.req.target_name),
              target, sizeof(rc.req.target_name) - 1);
    if (fn(MAGIC_HANDLE, (PVOID)key, OP_RESOLVE_TARGET, &rc, sizeof(rc)) != 0 ||
        rc.resp.status != 0) {
        printf("[!] RESOLVE_TARGET failed status=0x%x\n", rc.resp.status);
        return 3;
    }
    printf("[+] target=%s pid=%u image_base=0x%llx\n",
           target, rc.resp.target_pid, (unsigned long long)rc.resp.image_base);

    // Allocate destination buffer in our address space.
    uint8_t mz_buf[64] = {0};
    uint8_t section_buf[256] = {0};

    read_combo_t rd = {0};
    rd.req.target_pid  = rc.resp.target_pid;
    rd.req.entry_count = 2;
    rd.req.entries[0].src_va = rc.resp.image_base;
    rd.req.entries[0].dst_va = (uint64_t)(uintptr_t)mz_buf;
    rd.req.entries[0].len    = 64;
    // Read 256 bytes from offset 0x100 of target image (somewhere in PE
    // headers / first section).
    rd.req.entries[1].src_va = rc.resp.image_base + 0x100;
    rd.req.entries[1].dst_va = (uint64_t)(uintptr_t)section_buf;
    rd.req.entries[1].len    = 256;

    NTSTATUS s = fn(MAGIC_HANDLE, (PVOID)key, OP_READ_MANY, &rd, sizeof(rd));
    printf("[*] READ_MANY NTSTATUS=0x%lx, resp.status=0x%x\n", s, rd.resp.status);
    printf("    bytes_read[0]=%u (target image_base, expect 64)\n", rd.resp.bytes_read[0]);
    printf("    bytes_read[1]=%u (target image_base+0x100, expect 256)\n", rd.resp.bytes_read[1]);

    if (rd.resp.bytes_read[0] >= 2) {
        printf("    PE bytes[0..15] = ");
        for (int i = 0; i < 16; i++) printf("%02x ", mz_buf[i]);
        printf("\n");
        printf("    MZ check        = %s\n",
               (mz_buf[0] == 'M' && mz_buf[1] == 'Z') ? "PASS ('MZ')" : "FAIL");
    }

    fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
    return rd.resp.status;
}
