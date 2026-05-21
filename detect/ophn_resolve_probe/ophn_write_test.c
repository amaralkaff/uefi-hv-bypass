// ophn_write_test.c - Phase 6d: WRITE_MANY round-trip test.
//
// Strategy: REGISTER → RESOLVE_TARGET("DispCalAgent_xxx.exe") (resolve OUR
// own process so target_cr3 = caller_cr3) → READ a buffer of our own data
// → WRITE_MANY new data into a writable area in our own VA → READ back to
// confirm.
//
// Compile: cl /O2 /nologo ophn_write_test.c /Fe:ophn_write_test.exe

#include <intrin.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define OP_REGISTER         0x01
#define OP_RESOLVE_TARGET   0x02
#define OP_READ_MANY        0x03
#define OP_UNREGISTER       0x05
#define OP_WRITE_MANY       0x08
#define MAGIC_HANDLE        ((HANDLE)0xCAFEDEADBEEF1234ULL)
#define MAX_E               64

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

typedef struct { uint64_t src_va; uint64_t dst_va; uint32_t len; uint32_t reserved; } entry_t;
typedef struct { uint32_t pid; uint32_t entry_count; entry_t entries[MAX_E]; } io_req_t;
typedef struct { uint32_t bytes[MAX_E]; uint32_t status; uint32_t reserved; } io_resp_t;
typedef struct { io_req_t req; io_resp_t resp; } io_combo_t;

static char self_name[16] = {0};

static void
get_self_name(void)
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, sizeof(path));
    char *base = strrchr(path, '\\');
    base = base ? base + 1 : path;
    strncpy_s(self_name, sizeof(self_name), base, sizeof(self_name) - 1);
}

int main(void) {
    DWORD core = GetCurrentProcessorNumber();
    printf("core=%u\n", (unsigned)core);
    get_self_name();
    printf("self_name = '%s'\n", self_name);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PfnNtCreateCrossVmEvent fn = (PfnNtCreateCrossVmEvent)GetProcAddress(ntdll, "NtCreateCrossVmEvent");

    reg_combo_t reg = {0};
    HMODULE self = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((uint8_t *)self + dos->e_lfanew);
    reg.req.image_base = (uint64_t)(uintptr_t)self;
    reg.req.image_size = nt->OptionalHeader.SizeOfImage;
    if (fn(MAGIC_HANDLE, NULL, OP_REGISTER, &reg, sizeof(reg)) != 0 || reg.resp.status != 0) {
        printf("REGISTER failed\n"); return 1;
    }
    uint64_t key = reg.resp.session_key;

    resolve_combo_t rc = {0};
    strncpy_s(rc.req.target_name, sizeof(rc.req.target_name), self_name, sizeof(rc.req.target_name) - 1);
    if (fn(MAGIC_HANDLE, (PVOID)key, OP_RESOLVE_TARGET, &rc, sizeof(rc)) != 0 || rc.resp.status != 0) {
        printf("RESOLVE_TARGET self failed status=0x%x\n", rc.resp.status);
        // Diag: read OPHR sub 15 = last 12 bytes of EPROCESS.ImageFileName seen.
        int s15[4];
        __cpuidex(s15, 0x4F504852, 15);
        printf("    VMM last_name 12B: ");
        for (int i = 0; i < 12; i++) {
            int byte = (s15[1 + i / 4] >> ((i % 4) * 8)) & 0xFF;
            printf("%02x ", byte);
        }
        printf(" '");
        for (int i = 0; i < 12; i++) {
            int byte = (s15[1 + i / 4] >> ((i % 4) * 8)) & 0xFF;
            printf("%c", (byte >= 0x20 && byte < 0x7f) ? byte : '.');
        }
        printf("'\n");
        // Try with a wider name override.
        printf("[*] retry with full 'ophn_write_test.ex' (16 chars)\n");
        memset(rc.req.target_name, 0, sizeof(rc.req.target_name));
        strncpy_s(rc.req.target_name, sizeof(rc.req.target_name), "ophn_write_test.ex", sizeof(rc.req.target_name) - 1);
        memset(&rc.resp, 0, sizeof(rc.resp));
        fn(MAGIC_HANDLE, (PVOID)key, OP_RESOLVE_TARGET, &rc, sizeof(rc));
        printf("    retry status=0x%x pid=%u\n", rc.resp.status, rc.resp.pid);
        if (rc.resp.status != 0) {
            fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
            return 2;
        }
    }
    printf("[+] resolved self pid=%u image_base=0x%llx\n", rc.resp.pid, (unsigned long long)rc.resp.image_base);

    // Source = static stack data; dest = a writable global.
    static uint8_t dest_buf[64] = {0};
    uint8_t source[64];
    for (int i = 0; i < 64; i++) source[i] = (uint8_t)(0xC0 + i);

    static io_combo_t wc;
    memset(&wc, 0, sizeof(wc));
    wc.req.pid = rc.resp.pid;
    wc.req.entry_count = 1;
    wc.req.entries[0].src_va = (uint64_t)(uintptr_t)source;
    wc.req.entries[0].dst_va = (uint64_t)(uintptr_t)dest_buf;
    wc.req.entries[0].len    = 64;

    NTSTATUS s = fn(MAGIC_HANDLE, (PVOID)key, OP_WRITE_MANY, &wc, sizeof(wc));
    printf("[*] WRITE_MANY NTSTATUS=0x%lx, resp.status=0x%x, bytes=%u\n",
           s, wc.resp.status, wc.resp.bytes[0]);

    // Verify by direct memory read in our own process.
    printf("    dest_buf[0..15]: ");
    for (int i = 0; i < 16; i++) printf("%02x ", dest_buf[i]);
    printf("\n");
    int ok = 1;
    for (int i = 0; i < 64; i++) if (dest_buf[i] != source[i]) { ok = 0; break; }
    printf("    verify        : %s\n", ok ? "PASS" : "FAIL");

    fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
    return ok ? 0 : 3;
}
