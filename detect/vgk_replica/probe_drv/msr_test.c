/*
 * msr_test.c - direct comparison: BSP vs AP4 RDMSR(0x40000000)
 *
 * Build: cl /W4 /O2 msr_test.c
 *
 * BSP path = Ophion VMM virtualized core. AP4 = Phase 3 partial = bare metal.
 * If both return same 0x100000000 + gp=0 -> bare-metal Alder Lake quirk for
 * unimplemented MSR. If AP4 #GP's but BSP doesn't -> Ophion handler bug.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define IOCTL_PROBE_RDMSR     CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROBE_RDMSR_AP  CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct {
    uint32_t msr_index;
    uint64_t value;
    uint32_t gp_fired;
    uint32_t cpu_before;
    uint32_t cpu_after;
} rdmsr_req_t;
#pragma pack(pop)

static void
do_rdmsr(HANDLE h, DWORD ioctl, uint32_t msr, const char *label)
{
    rdmsr_req_t req = { .msr_index = msr };
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, ioctl, &req, sizeof(req), &req, sizeof(req), &bytes, NULL);
    if (!ok) {
        printf("[%s] MSR 0x%08x ioctl FAILED err=%lu\n", label, msr, GetLastError());
        return;
    }
    printf("[%s] MSR 0x%08x cpu_before=%u cpu_after=%u gp=%u value=0x%016llx\n",
           label, msr, req.cpu_before, req.cpu_after, req.gp_fired,
           (unsigned long long)req.value);
}

int
main(void)
{
    HANDLE h = CreateFileA("\\\\.\\VgkProbeDrv", GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "open VgkProbeDrv failed err=%lu\n", GetLastError());
        return 1;
    }

    static const uint32_t msrs[] = {
        0x40000000,  // HV synthetic GUEST_OS_ID
        0x40000001,  // HV synthetic HYPERCALL
        0xDEADBEEF,  // unimplemented control sample (out of bitmap, NOT in HV range)
        0x000001D9,  // IA32_DEBUGCTL (in bitmap, no exit)
    };

    printf("=== MSR comparison: BSP (virtualized) vs AP4 (bare) ===\n");
    for (size_t i = 0; i < sizeof(msrs)/sizeof(msrs[0]); ++i) {
        do_rdmsr(h, IOCTL_PROBE_RDMSR,    msrs[i], "BSP");
        do_rdmsr(h, IOCTL_PROBE_RDMSR_AP, msrs[i], "AP4");
        printf("\n");
    }

    CloseHandle(h);
    return 0;
}
