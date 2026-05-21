/*
 * cpuid_checks.c - CPUID-family probes
 *
 * Mirrors hxv part 19 kHvSignatures + CPUMODEL_BIT_* dashboard catalog. Any
 * positive hit on a hypervisor signature short-circuits to PROBE_FAIL with
 * detail string identifying which signature matched, so the user can map back
 * to which Ophion stealth path needs work.
 */
#include "vgk_probe.h"
#include <intrin.h>
#include <string.h>
#include <stdio.h>

// vgk's kHvSignatures table reproduced verbatim. Any of these as the
// 12-char CPUID 0x40000000 vendor string is an immediate ban signal.
static const struct {
    const char *signature;
    const char *vendor_label;
} kHvSignatures[] = {
    { "VMwareVMware", "VMware"     },
    { "VBoxVBoxVBox", "VirtualBox" },
    { "Microsoft Hv", "Hyper-V"    },
    { "KVMKVMKVM\0\0\0", "KVM"     },
    { "TCGTCGTCGTCG", "QEMU/TCG"   },
    { "XenVMMXenVMM", "Xen"        },
    { "prl hyperv  ", "Parallels"  },
    { "bhyve bhyve ", "bhyve"      },
};

probe_outcome_t
probe_cpuid_hv_present_bit(void)
{
    probe_outcome_t r = {
        .name = "cpuid_hv_present_bit",
        .category = "cpuid",
        .result = PROBE_PASS,
    };

    int regs[4];
    __cpuid(regs, 1);
    if (regs[2] & (1u << 31)) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail),
                 "CPUID.1.ECX[31] set; bare metal returns 0");
    }
    return r;
}

probe_outcome_t
probe_cpuid_leaf_0x40000000(void)
{
    probe_outcome_t r = {
        .name = "cpuid_leaf_0x40000000_zeroed",
        .category = "cpuid",
        .result = PROBE_PASS,
    };

    int regs[4];
    __cpuid(regs, 0x40000000);

    // Bare metal returns either all zeros OR the value cached from an
    // out-of-range leaf (typically the max-extended-leaf response).
    // Ophion's vmexit_handle_cpuid passes through to bare metal, so a
    // healthy stealth posture returns identical bytes either way.
    if (regs[0] == 0 && regs[1] == 0 && regs[2] == 0 && regs[3] == 0) {
        return r;
    }

    // Non-zero result: check whether the EBX/ECX/EDX form a known HV vendor
    // string. If so, FAIL with vendor label.
    char vendor[13] = {0};
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);

    for (size_t i = 0; i < sizeof(kHvSignatures) / sizeof(kHvSignatures[0]); ++i) {
        if (memcmp(vendor, kHvSignatures[i].signature, 12) == 0) {
            r.result = PROBE_FAIL;
            snprintf(r.detail, sizeof(r.detail),
                     "CPUID.0x40000000 vendor = '%s' (%s)",
                     vendor, kHvSignatures[i].vendor_label);
            return r;
        }
    }

    // Non-zero but vendor doesn't match any known HV signature. Two benign cases:
    //   a) Cached out-of-range response (matches CPUID.0x80000000 max-extended-leaf).
    //   b) Firmware quirk on bare metal (Alder Lake i5-12400F observed:
    //      EAX=0,EBX=1,ECX=0,EDX=0). EAX=0 means CPU is NOT advertising any
    //      hypervisor leaf range, so it cannot be a real HV. Real Vanguard /
    //      vmaware only flag when vendor string matches kHvSignatures or EAX
    //      reports a valid max-HV-leaf >= 0x40000001.
    int max_ext[4];
    __cpuid(max_ext, 0x80000000);
    if (regs[0] == max_ext[0] && regs[1] == max_ext[1] &&
        regs[2] == max_ext[2] && regs[3] == max_ext[3]) {
        return r;
    }

    // EAX < 0x40000001 means no advertised HV leaf range -> not a hypervisor.
    if ((uint32_t)regs[0] < 0x40000001u) {
        snprintf(r.detail, sizeof(r.detail),
                 "CPUID.0x40000000 = %08x:%08x:%08x:%08x (no HV vendor, EAX advertises no HV leaves; firmware quirk, not flagged)",
                 regs[0], regs[1], regs[2], regs[3]);
        return r;
    }

    r.result = PROBE_FAIL;
    snprintf(r.detail, sizeof(r.detail),
             "CPUID.0x40000000 = %08x:%08x:%08x:%08x (non-zero, non-cached, unknown vendor '%s')",
             regs[0], regs[1], regs[2], regs[3], vendor);
    return r;
}

probe_outcome_t
probe_cpuid_hyperv_root_partition(void)
{
    probe_outcome_t r = {
        .name = "cpuid_hyperv_root_partition",
        .category = "cpuid",
        .result = PROBE_PASS,
    };

    // vmaware is_root_partition probes CPUID 0x40000003 sub-leaf 0xF. EBX
    // bit 0 set = root partition. Bare metal returns 0 for this sub-leaf
    // (out-of-range, cached as zero unless firmware did something weird).
    int regs[4];
    __cpuidex(regs, 0x40000003, 0xF);

    if (regs[1] & 1u) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail),
                 "CPUID.0x40000003.subleaf=0xF EBX[0] set (Hyper-V root partition flag)");
    }
    return r;
}

probe_outcome_t
probe_cpuid_hv_signatures_scan(void)
{
    probe_outcome_t r = {
        .name = "cpuid_hv_signatures_full_scan",
        .category = "cpuid",
        .result = PROBE_PASS,
    };

    // vgk scans leaves 0x40000000..0x400000FF. We sample every 0x100 step.
    for (uint32_t leaf = 0x40000000; leaf < 0x40000100; leaf += 0x10) {
        int regs[4];
        __cpuid(regs, (int)leaf);

        char vendor[13] = {0};
        memcpy(vendor + 0, &regs[1], 4);
        memcpy(vendor + 4, &regs[2], 4);
        memcpy(vendor + 8, &regs[3], 4);

        for (size_t i = 0; i < sizeof(kHvSignatures) / sizeof(kHvSignatures[0]); ++i) {
            if (memcmp(vendor, kHvSignatures[i].signature, 12) == 0) {
                r.result = PROBE_FAIL;
                snprintf(r.detail, sizeof(r.detail),
                         "leaf 0x%08x matches %s signature",
                         leaf, kHvSignatures[i].vendor_label);
                return r;
            }
        }
    }
    return r;
}
