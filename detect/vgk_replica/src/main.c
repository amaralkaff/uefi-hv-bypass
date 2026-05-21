/*
 * main.c - vgk_probe CLI entry
 *
 * Usage:
 *   vgk_probe.exe --calibrate         Capture bare-metal RDTSC-CPUID baseline
 *   vgk_probe.exe --check             Run all probes
 *   vgk_probe.exe --check --json      Machine-readable JSON output
 *
 * Exit codes:
 *   0 = all probes PASS
 *   1 = at least one FAIL
 *   2 = SKIP (privileged probes need probe_drv loaded)
 *   3 = NEEDS_CALIB (run --calibrate first)
 *   4 = usage / arg error
 */
#include "vgk_probe.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *
result_str(probe_result_t r)
{
    switch (r) {
    case PROBE_PASS:        return "PASS";
    case PROBE_FAIL:        return "FAIL";
    case PROBE_SKIP:        return "SKIP";
    case PROBE_NEEDS_CALIB: return "NEEDS_CALIB";
    }
    return "?";
}

int
probe_run_all(probe_report_t *out, const timing_baseline_t *baseline)
{
    memset(out, 0, sizeof(*out));

    probe_outcome_t (*tests[])(void) = {
        probe_cpuid_hv_present_bit,
        probe_cpuid_leaf_0x40000000,
        probe_cpuid_hyperv_root_partition,
        probe_cpuid_hv_signatures_scan,
        probe_msr_hv_range_gp,
        probe_msr_ia32_debugctl_lbr,
        probe_cr4_smep_at_idle,
        probe_cr4_smap_at_idle,
        probe_cr4_osxsave,
        probe_nic_mac_oui,
        probe_smbios_uuid_wellformed,
        probe_smbios_vendor_strings,
        probe_topology_processor_count,
        probe_topology_apic_consistency,
    };

    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
        out->outcomes[out->outcome_count++] = tests[i]();
    }

    // Timing probe needs baseline arg, run separately.
    out->outcomes[out->outcome_count++] = probe_timing_rdtsc_cpuid_delta(baseline);

    for (int i = 0; i < out->outcome_count; ++i) {
        switch (out->outcomes[i].result) {
        case PROBE_PASS: out->pass_count++; break;
        case PROBE_FAIL: out->fail_count++; break;
        case PROBE_SKIP: out->skip_count++; break;
        case PROBE_NEEDS_CALIB: out->fail_count++; break;
        }
    }
    return 0;
}

void
probe_emit_console(const probe_report_t *report)
{
    printf("=== vgk_probe v%s ===\n", VGK_PROBE_VERSION);
    for (int i = 0; i < report->outcome_count; ++i) {
        const probe_outcome_t *o = &report->outcomes[i];
        printf("[%-11s] %-40s (%-8s) %s\n",
               result_str(o->result), o->name, o->category, o->detail);
    }
    printf("\nSummary: %d pass / %d fail / %d skip\n",
           report->pass_count, report->fail_count, report->skip_count);
}

int
probe_emit_json(const probe_report_t *report, char *buf, size_t buf_size)
{
    int n = snprintf(buf, buf_size,
        "{\n  \"version\": \"%s\",\n  \"summary\": { \"pass\": %d, \"fail\": %d, \"skip\": %d },\n  \"outcomes\": [\n",
        VGK_PROBE_VERSION,
        report->pass_count, report->fail_count, report->skip_count);

    for (int i = 0; i < report->outcome_count; ++i) {
        const probe_outcome_t *o = &report->outcomes[i];
        n += snprintf(buf + n, (n < (int)buf_size) ? (buf_size - n) : 0,
            "    { \"name\": \"%s\", \"category\": \"%s\", \"result\": \"%s\", \"detail\": \"%s\" }%s\n",
            o->name, o->category, result_str(o->result), o->detail,
            (i + 1 < report->outcome_count) ? "," : "");
    }
    n += snprintf(buf + n, (n < (int)buf_size) ? (buf_size - n) : 0, "  ]\n}\n");
    return n;
}

static int
usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --calibrate            Capture bare-metal baseline (run on clean Windows)\n"
        "  %s --check                Run all probes\n"
        "  %s --check --json         JSON output\n",
        prog, prog, prog);
    return 4;
}

int
main(int argc, char **argv)
{
    if (argc < 2) return usage(argv[0]);

    int do_calibrate = 0, do_check = 0, json = 0;
    for (int i = 1; i < argc; ++i) {
        if      (!strcmp(argv[i], "--calibrate")) do_calibrate = 1;
        else if (!strcmp(argv[i], "--check"))     do_check     = 1;
        else if (!strcmp(argv[i], "--json"))      json         = 1;
        else return usage(argv[0]);
    }

    if (do_calibrate) {
        timing_baseline_t b;
        if (!calibration_capture_baseline(&b)) {
            fprintf(stderr, "calibrate: capture failed\n");
            return 1;
        }
        if (!calibration_save_baseline(&b)) {
            fprintf(stderr, "calibrate: save failed\n");
            return 1;
        }
        printf("Baseline captured: cpu=%s p50=%llu p99=%llu max=%llu cycles\n",
               b.cpu_brand,
               (unsigned long long)b.rdtsc_cpuid_delta_p50,
               (unsigned long long)b.rdtsc_cpuid_delta_p99,
               (unsigned long long)b.rdtsc_cpuid_delta_max);
        return 0;
    }

    if (!do_check) return usage(argv[0]);

    timing_baseline_t baseline;
    int have_baseline = calibration_load_baseline(&baseline);

    probe_report_t report;
    probe_run_all(&report, have_baseline ? &baseline : NULL);

    if (json) {
        static char buf[16384];
        probe_emit_json(&report, buf, sizeof(buf));
        fputs(buf, stdout);
    } else {
        probe_emit_console(&report);
    }

    if (report.fail_count > 0) return 1;
    if (report.skip_count > 0) return 2;
    return 0;
}
