/*
 * vgk_probe.h - Vanguard-replica detection probe suite
 *
 * Replicates the checks vgk.sys performs at runtime so Ophion's stealth
 * posture can be validated before exposing any account to live Vanguard.
 *
 * Coverage map (sources: hxv full analysis 2026, vgkey/src corpus):
 *   - CPUID leaf 0x40000000-0x400000FF must return zero (no HV signature)
 *   - CPUID leaf 1 ECX[31] (hypervisor present) must be clear
 *   - CPUID leaf 0x40000003 sub-leaf 0xF (Hyper-V root partition bit)
 *   - MSR sweep 0x40000000-0x4FFFFFFF must inject #GP (no synthetic MSRs)
 *   - CR4.SMEP (bit 20), CR4.SMAP (bit 21), CR4.OSXSAVE (bit 18) at idle
 *   - IA32_DEBUGCTL bit 0 (LBR) must remain set across kernel reads
 *   - RDTSC pre/post CPUID delta within 3x bare-metal baseline
 *   - MAC OUI not in vgk anti-VM blocklist (VMware/VBox/Hyper-V/KVM/Parallels)
 *   - SMBIOS UUID well-formed (not all-zeros / all-FFs)
 *   - DMI/ACPI vendor strings not flagged (no "QEMU", "innotek", "VirtualBox")
 *
 * Run modes:
 *   --calibrate : capture bare-metal RDTSC-CPUID baseline (run on clean Windows
 *                 without any HV). Stored to %LOCALAPPDATA%\vgk_probe\baseline.json
 *   --check     : run all probes against current state, compare to baseline
 *   --json      : emit machine-readable JSON for CI
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#define VGK_PROBE_VERSION "0.1.0"

typedef enum {
    PROBE_PASS = 0,
    PROBE_FAIL,
    PROBE_SKIP,        // privileged probe in user-mode build
    PROBE_NEEDS_CALIB, // calibration not run yet
} probe_result_t;

typedef struct {
    const char *name;
    const char *category;       // "cpuid", "msr", "cr", "timing", "topology", "nic", "smbios"
    probe_result_t result;
    char detail[256];           // human-readable explanation on fail
} probe_outcome_t;

typedef struct {
    uint64_t rdtsc_cpuid_delta_p50;    // 50th percentile cycles
    uint64_t rdtsc_cpuid_delta_p99;    // 99th percentile cycles
    uint64_t rdtsc_cpuid_delta_max;
    uint32_t sample_count;
    char     cpu_brand[64];
    uint32_t cpu_family;
    uint32_t cpu_model;
} timing_baseline_t;

// CPUID family
probe_outcome_t probe_cpuid_hv_present_bit(void);
probe_outcome_t probe_cpuid_leaf_0x40000000(void);
probe_outcome_t probe_cpuid_hyperv_root_partition(void);
probe_outcome_t probe_cpuid_hv_signatures_scan(void);  // sweep known vendor strings

// MSR family (requires kernel probe driver, returns PROBE_SKIP in user-mode build)
probe_outcome_t probe_msr_hv_range_gp(void);
probe_outcome_t probe_msr_ia32_debugctl_lbr(void);

// CR family (requires kernel probe driver)
probe_outcome_t probe_cr4_smep_at_idle(void);
probe_outcome_t probe_cr4_smap_at_idle(void);
probe_outcome_t probe_cr4_osxsave(void);

// Timing
probe_outcome_t probe_timing_rdtsc_cpuid_delta(const timing_baseline_t *baseline);

// Topology
probe_outcome_t probe_topology_processor_count(void);
probe_outcome_t probe_topology_apic_consistency(void);

// NIC
probe_outcome_t probe_nic_mac_oui(void);

// SMBIOS
probe_outcome_t probe_smbios_uuid_wellformed(void);
probe_outcome_t probe_smbios_vendor_strings(void);

// Calibration
int calibration_capture_baseline(timing_baseline_t *out);
int calibration_load_baseline(timing_baseline_t *out);
int calibration_save_baseline(const timing_baseline_t *baseline);

// Runner
typedef struct {
    probe_outcome_t outcomes[64];
    int outcome_count;
    int pass_count;
    int fail_count;
    int skip_count;
} probe_report_t;

int probe_run_all(probe_report_t *out, const timing_baseline_t *baseline);
int probe_emit_json(const probe_report_t *report, char *buf, size_t buf_size);
void probe_emit_console(const probe_report_t *report);
