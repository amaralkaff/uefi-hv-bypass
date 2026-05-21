/*
 * msr_cr_checks.c - MSR-sweep + CR4 probes
 *
 * Privileged operations. User-mode build returns PROBE_SKIP. A kernel
 * companion driver (probe_drv/) handles real reads when loaded; this file
 * talks to it via IOCTL when available, else skips.
 */
#include "vgk_probe.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define PROBE_DRV_DEVICE_NAME  "\\\\.\\VgkProbeDrv"
#define IOCTL_PROBE_RDMSR      CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROBE_READCR4    CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROBE_READDEBUGCTL CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct {
    uint32_t msr_index;
    uint64_t value;        // out
    uint32_t gp_fired;     // out (1 if #GP injected)
    uint32_t cpu_before;   // out
    uint32_t cpu_after;    // out
} rdmsr_req_t;
#pragma pack(pop)

static HANDLE
open_probe_drv(void)
{
    return CreateFileA(PROBE_DRV_DEVICE_NAME,
                       GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);
}

static int
drv_read_msr(HANDLE h, uint32_t msr, uint64_t *value_out, int *gp_fired)
{
    rdmsr_req_t req = { .msr_index = msr };
    DWORD bytes = 0;
    if (!DeviceIoControl(h, IOCTL_PROBE_RDMSR,
                         &req, sizeof(req),
                         &req, sizeof(req),
                         &bytes, NULL)) {
        return 0;
    }
    if (value_out) *value_out = req.value;
    if (gp_fired)  *gp_fired  = (int)req.gp_fired;
    return 1;
}

static int
drv_read_msr_ex(HANDLE h, uint32_t msr, rdmsr_req_t *out)
{
    rdmsr_req_t req = { .msr_index = msr };
    DWORD bytes = 0;
    if (!DeviceIoControl(h, IOCTL_PROBE_RDMSR,
                         &req, sizeof(req),
                         &req, sizeof(req),
                         &bytes, NULL)) {
        return 0;
    }
    if (out) *out = req;
    return 1;
}

static int
drv_read_cr4(HANDLE h, uint64_t *cr4_out)
{
    DWORD bytes = 0;
    return !!DeviceIoControl(h, IOCTL_PROBE_READCR4,
                             NULL, 0,
                             cr4_out, sizeof(*cr4_out),
                             &bytes, NULL);
}

static int
drv_read_debugctl(HANDLE h, uint64_t *out)
{
    DWORD bytes = 0;
    return !!DeviceIoControl(h, IOCTL_PROBE_READDEBUGCTL,
                             NULL, 0,
                             out, sizeof(*out),
                             &bytes, NULL);
}

probe_outcome_t
probe_msr_hv_range_gp(void)
{
    probe_outcome_t r = {
        .name = "msr_hv_synthetic_range_gp",
        .category = "msr",
        .result = PROBE_PASS,
    };

    HANDLE h = open_probe_drv();
    if (h == INVALID_HANDLE_VALUE) {
        r.result = PROBE_SKIP;
        snprintf(r.detail, sizeof(r.detail),
                 "probe_drv not loaded; load VgkProbeDrv to enable");
        return r;
    }

    // Sweep typical Hyper-V / KVM synthetic MSR slots. Bare metal #GP's.
    static const uint32_t probe_slots[] = {
        0x40000000,  // Hyper-V synthetic guest os id
        0x40000001,  // Hyper-V hypercall page
        0x40000020,  // Hyper-V vp index
        0x4B564D00,  // KVM wall clock
        0x4B564D01,  // KVM system time
        0x4B564D02,  // KVM async pf
    };

    for (size_t i = 0; i < sizeof(probe_slots) / sizeof(probe_slots[0]); ++i) {
        rdmsr_req_t req2 = {0};
        if (!drv_read_msr_ex(h, probe_slots[i], &req2)) {
            r.result = PROBE_FAIL;
            snprintf(r.detail, sizeof(r.detail),
                     "drv ioctl failed for MSR 0x%x", probe_slots[i]);
            CloseHandle(h);
            return r;
        }
        uint64_t val = req2.value;
        int gp = (int)req2.gp_fired;
        if (!gp) {
            r.result = PROBE_FAIL;
            snprintf(r.detail, sizeof(r.detail),
                     "MSR 0x%x val=0x%llx cpu_before=%u cpu_after=%u (no #GP)",
                     probe_slots[i], (unsigned long long)val,
                     (unsigned)req2.cpu_before, (unsigned)req2.cpu_after);
            CloseHandle(h);
            return r;
        }
    }
    CloseHandle(h);
    return r;
}

probe_outcome_t
probe_msr_ia32_debugctl_lbr(void)
{
    probe_outcome_t r = {
        .name = "msr_ia32_debugctl_lbr_set",
        .category = "msr",
        .result = PROBE_PASS,
    };

    HANDLE h = open_probe_drv();
    if (h == INVALID_HANDLE_VALUE) {
        r.result = PROBE_SKIP;
        snprintf(r.detail, sizeof(r.detail), "probe_drv not loaded");
        return r;
    }

    uint64_t debugctl = 0;
    if (!drv_read_debugctl(h, &debugctl)) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail), "drv ioctl failed");
        CloseHandle(h);
        return r;
    }
    CloseHandle(h);

    // Idle Win10 + Alder Lake: bit 0 (LBR) typically OFF. Real vgk canary
    // WRMSRs to enable LBR then reads the ring. Idle probe can't test
    // VMM passthrough without WRMSR ioctl (out of scope here). Treat as
    // SKIP — real verification needs bench HW + Vanguard.
    snprintf(r.detail, sizeof(r.detail),
             "IA32_DEBUGCTL=0x%llx (idle state; real LBR test = bench HW)",
             (unsigned long long)debugctl);
    r.result = PROBE_SKIP;
    return r;
}

static probe_outcome_t
cr4_bit_probe(const char *name, uint64_t bit_mask, const char *bit_label)
{
    probe_outcome_t r = {
        .name = name,
        .category = "cr",
        .result = PROBE_PASS,
    };

    HANDLE h = open_probe_drv();
    if (h == INVALID_HANDLE_VALUE) {
        r.result = PROBE_SKIP;
        snprintf(r.detail, sizeof(r.detail), "probe_drv not loaded");
        return r;
    }

    uint64_t cr4 = 0;
    if (!drv_read_cr4(h, &cr4)) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail), "drv ioctl failed");
        CloseHandle(h);
        return r;
    }
    CloseHandle(h);

    if (!(cr4 & bit_mask)) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail),
                 "CR4=0x%llx %s clear; vgk enforcement expects set",
                 (unsigned long long)cr4, bit_label);
    } else {
        snprintf(r.detail, sizeof(r.detail),
                 "CR4=0x%llx %s set", (unsigned long long)cr4, bit_label);
    }
    return r;
}

probe_outcome_t probe_cr4_smep_at_idle(void) {
    probe_outcome_t r = cr4_bit_probe("cr4_smep_at_idle", 1ULL << 20, "SMEP(bit20)");
    return r;
}

probe_outcome_t probe_cr4_smap_at_idle(void) {
    probe_outcome_t r = cr4_bit_probe("cr4_smap_at_idle", 1ULL << 21, "SMAP(bit21)");
    return r;
}

probe_outcome_t probe_cr4_osxsave(void) {
    probe_outcome_t r = cr4_bit_probe("cr4_osxsave", 1ULL << 18, "OSXSAVE(bit18)");
    return r;
}
