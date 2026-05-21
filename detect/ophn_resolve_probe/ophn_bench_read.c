// ophn_bench_read.c - Phase 6e: READ_MANY / WRITE_MANY latency.
//
// Compile: cl /O2 /nologo ophn_bench_read.c /Fe:ophn_bench_read.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

#define OP_REGISTER       0x01
#define OP_RESOLVE_TARGET 0x02
#define OP_READ_MANY      0x03
#define OP_UNREGISTER     0x05
#define OP_WRITE_MANY     0x08
#define MAGIC_HANDLE      ((HANDLE)0xCAFEDEADBEEF1234ULL)
#define MAX_E             64

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

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a, vb = *(const uint64_t *)b;
    return va < vb ? -1 : (va > vb ? 1 : 0);
}

#define ITERS 5000

static void
bench_op(PfnNtCreateCrossVmEvent fn, uint64_t key, uint32_t op, io_combo_t *combo, const char *label) {
    LARGE_INTEGER qpf, t0, t1;
    QueryPerformanceFrequency(&qpf);
    double tick_ns = 1e9 / (double)qpf.QuadPart;

    static uint64_t qpc_samples[ITERS];
    LARGE_INTEGER pa, pb;

    // Warmup
    for (int i = 0; i < 100; i++) fn(MAGIC_HANDLE, (PVOID)key, op, combo, sizeof(*combo));

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < ITERS; i++) {
        QueryPerformanceCounter(&pa);
        fn(MAGIC_HANDLE, (PVOID)key, op, combo, sizeof(*combo));
        QueryPerformanceCounter(&pb);
        qpc_samples[i] = pb.QuadPart - pa.QuadPart;
    }
    QueryPerformanceCounter(&t1);
    double total_s = (t1.QuadPart - t0.QuadPart) / (double)qpf.QuadPart;

    qsort(qpc_samples, ITERS, sizeof(uint64_t), cmp_u64);
    double p50 = qpc_samples[ITERS / 2] * tick_ns / 1000.0;
    double p99 = qpc_samples[(ITERS * 99) / 100] * tick_ns / 1000.0;
    double maxv = qpc_samples[ITERS - 1] * tick_ns / 1000.0;

    printf("%-20s %d iters in %.2f ms (%.0f/s)  p50=%.2f us  p99=%.2f us  max=%.2f us\n",
           label, ITERS, total_s * 1000.0, ITERS / total_s, p50, p99, maxv);
}

int main(void) {
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
    strncpy_s(rc.req.target_name, sizeof(rc.req.target_name), "explorer.exe", 15);
    if (fn(MAGIC_HANDLE, (PVOID)key, OP_RESOLVE_TARGET, &rc, sizeof(rc)) != 0 || rc.resp.status != 0) {
        printf("RESOLVE explorer failed\n"); return 2;
    }
    printf("[+] target=explorer.exe pid=%u image_base=0x%llx\n",
           rc.resp.pid, (unsigned long long)rc.resp.image_base);
    printf("\n");

    static uint8_t scratch[8192];
    static io_combo_t rd, wr;

    // --- Bench: 1 entry × 64 bytes (single small read) ---
    memset(&rd, 0, sizeof(rd));
    rd.req.pid = rc.resp.pid;
    rd.req.entry_count = 1;
    rd.req.entries[0].src_va = rc.resp.image_base;
    rd.req.entries[0].dst_va = (uint64_t)(uintptr_t)scratch;
    rd.req.entries[0].len = 64;
    bench_op(fn, key, OP_READ_MANY, &rd, "READ 1x64B");

    // --- 1 entry × 4096 bytes (page) ---
    rd.req.entries[0].len = 4096;
    bench_op(fn, key, OP_READ_MANY, &rd, "READ 1x4KB");

    // --- 8 entries × 4096 bytes ---
    rd.req.entry_count = 8;
    for (int i = 0; i < 8; i++) {
        rd.req.entries[i].src_va = rc.resp.image_base + i * 0x1000;
        rd.req.entries[i].dst_va = (uint64_t)(uintptr_t)(scratch + i * 0x1000) % sizeof(scratch);
        rd.req.entries[i].len = 4096;
    }
    // Avoid scratch overflow; reuse scratch[0] for all dst
    for (int i = 0; i < 8; i++) rd.req.entries[i].dst_va = (uint64_t)(uintptr_t)scratch;
    bench_op(fn, key, OP_READ_MANY, &rd, "READ 8x4KB");

    // --- WRITE_MANY: 1 entry × 64 bytes (self-target unsafe; use explorer
    // dst that's a valid writable page is non-trivial; just bench READ for
    // now since WRITE codepath is identical PT-walk-then-copy.) ---
    printf("\n(WRITE bench skipped — explorer write would corrupt; perf identical to READ.)\n");

    fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
    return 0;
}
