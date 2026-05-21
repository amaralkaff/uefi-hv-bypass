// ophn_bench.c - Phase 6e: VMCALL channel latency benchmark.
//
// Measures round-trip latency for STATUS_QUERY across many iterations.
// VMCALL path: ntdll stub → ntos patched body → trampoline → vmexit →
// VmcallDispatch → vmm_guest_read/write → vmresume → ret → user.
//
// Target: <100us/call → 60fps loop has ~16ms budget = ~160 calls/frame.
// >1ms/call → channel too slow for tight per-frame use.
//
// Compile: cl /O2 /nologo ophn_bench.c /Fe:ophn_bench.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#define OP_REGISTER     0x01
#define OP_STATUS_QUERY 0x04
#define OP_UNREGISTER   0x05
#define MAGIC_HANDLE    ((HANDLE)0xCAFEDEADBEEF1234ULL)

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PfnNtCreateCrossVmEvent)(HANDLE, PVOID, ULONG, PVOID, ULONG);

#pragma pack(push, 1)
typedef struct { uint8_t image_sha256[32]; uint64_t image_base; uint32_t image_size; uint32_t reserved; } reg_req_t;
typedef struct { uint64_t session_key; uint32_t version; uint32_t status; } reg_resp_t;
typedef struct { reg_req_t req; reg_resp_t resp; } reg_combo_t;
#pragma pack(pop)

typedef struct {
    uint32_t ophion_loaded;
    uint32_t ophion_version;
    uint32_t patch_applied;
    uint32_t ntos_build_known;
    uint64_t vmm_uptime_ms;
} status_resp_t;

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a, vb = *(const uint64_t *)b;
    return va < vb ? -1 : (va > vb ? 1 : 0);
}

#define ITERS 10000

int main(void) {
    DWORD core = GetCurrentProcessorNumber();
    printf("core=%u  iters=%d\n", (unsigned)core, ITERS);

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
        printf("REGISTER failed\n"); return 1;
    }
    uint64_t key = reg.resp.session_key;
    printf("[+] registered key=0x%llx\n", (unsigned long long)key);

    LARGE_INTEGER qpf;
    QueryPerformanceFrequency(&qpf);
    double tick_ns = 1e9 / (double)qpf.QuadPart;
    printf("[+] QPC freq=%lld Hz (tick=%.2f ns)\n", qpf.QuadPart, tick_ns);

    // TSC for cycle-accurate timing.
    static uint64_t tsc_samples[ITERS];
    static uint64_t qpc_samples[ITERS];
    status_resp_t st;

    // Warmup
    for (int i = 0; i < 100; i++) {
        memset(&st, 0, sizeof(st));
        fn(MAGIC_HANDLE, (PVOID)key, OP_STATUS_QUERY, &st, sizeof(st));
    }

    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < ITERS; i++) {
        unsigned aux;
        uint64_t a = __rdtscp(&aux);
        LARGE_INTEGER pa, pb;
        QueryPerformanceCounter(&pa);
        memset(&st, 0, sizeof(st));
        fn(MAGIC_HANDLE, (PVOID)key, OP_STATUS_QUERY, &st, sizeof(st));
        QueryPerformanceCounter(&pb);
        uint64_t b = __rdtscp(&aux);
        tsc_samples[i] = b - a;
        qpc_samples[i] = pb.QuadPart - pa.QuadPart;
    }
    QueryPerformanceCounter(&t1);
    double total_s = (t1.QuadPart - t0.QuadPart) / (double)qpf.QuadPart;

    qsort(tsc_samples, ITERS, sizeof(uint64_t), cmp_u64);
    qsort(qpc_samples, ITERS, sizeof(uint64_t), cmp_u64);

    double tsc_p50_us = 0, tsc_p99_us = 0;
    // No published TSC freq from CPUID 0x15 here; assume 2.5GHz nominal.
    // Convert via QPC-derived ratio: total_s vs sum(qpc_samples) is exact.
    double qpc_p50_us = qpc_samples[ITERS / 2] * tick_ns / 1000.0;
    double qpc_p99_us = qpc_samples[(ITERS * 99) / 100] * tick_ns / 1000.0;
    double qpc_min_us = qpc_samples[0] * tick_ns / 1000.0;
    double qpc_max_us = qpc_samples[ITERS - 1] * tick_ns / 1000.0;

    printf("\n=== %d STATUS_QUERY round-trips ===\n", ITERS);
    printf("Total wall    : %.2f ms (%.0f calls/s, %.2f us/call avg)\n",
           total_s * 1000.0,
           ITERS / total_s,
           total_s * 1e6 / ITERS);
    printf("QPC per-call  : min=%.2f us  p50=%.2f us  p99=%.2f us  max=%.2f us\n",
           qpc_min_us, qpc_p50_us, qpc_p99_us, qpc_max_us);
    printf("TSC per-call  : p50=%llu cycles  p99=%llu cycles  max=%llu cycles\n",
           (unsigned long long)tsc_samples[ITERS / 2],
           (unsigned long long)tsc_samples[(ITERS * 99) / 100],
           (unsigned long long)tsc_samples[ITERS - 1]);

    double budget_60fps_us = 16666.67;
    printf("\n[60fps budget] %.0f us/frame → max %.0f calls/frame at p50\n",
           budget_60fps_us, budget_60fps_us / qpc_p50_us);

    fn(MAGIC_HANDLE, (PVOID)key, OP_UNREGISTER, NULL, 0);
    return 0;
}
