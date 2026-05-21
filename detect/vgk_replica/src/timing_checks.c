/*
 * timing_checks.c - RDTSC-CPUID-RDTSC delta probe + bare-metal calibration
 *
 * vgk does not directly time CPUID this way, but vmaware/hvdetecc do; matching
 * bare-metal latency closes a public detection vector that any tool with
 * vgk-class privileges could use. Ophion's STEALTH_COMPENSATE_TIMING returns
 * compensated TSC values for the RDTSC after a CPUID exit, so the delta should
 * land within 2-3x of the bare-metal baseline captured during --calibrate.
 *
 * Methodology:
 *   - Pre-warm: 1000 CPUIDs to populate microarchitectural state.
 *   - Measure: 10000 RDTSC -> CPUID(1) -> RDTSC samples.
 *   - Aggregate: p50 / p99 / max cycles over samples (drop outliers > 10x p99).
 *   - On --calibrate: store baseline.
 *   - On --check: fail if current p99 > 3 * baseline_p99.
 *
 * Stored at %LOCALAPPDATA%\vgk_probe\baseline.json
 */
#include "vgk_probe.h"
#include <intrin.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <shlobj.h>

#define TIMING_PREWARM    1000
#define TIMING_SAMPLES    10000

static int
cmp_u64(const void *a, const void *b)
{
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

static int
get_cpu_brand(char *out, size_t out_size)
{
    int regs[4];
    char brand[49] = {0};

    __cpuid(regs, 0x80000000);
    if ((uint32_t)regs[0] < 0x80000004u) {
        snprintf(out, out_size, "unknown");
        return 0;
    }

    __cpuid(regs, 0x80000002); memcpy(brand + 0,  regs, 16);
    __cpuid(regs, 0x80000003); memcpy(brand + 16, regs, 16);
    __cpuid(regs, 0x80000004); memcpy(brand + 32, regs, 16);

    snprintf(out, out_size, "%s", brand);
    return 1;
}

static int
get_cpu_family_model(uint32_t *family, uint32_t *model)
{
    int regs[4];
    __cpuid(regs, 1);
    uint32_t base_family = (regs[0] >> 8) & 0xF;
    uint32_t base_model  = (regs[0] >> 4) & 0xF;
    uint32_t ext_family  = (regs[0] >> 20) & 0xFF;
    uint32_t ext_model   = (regs[0] >> 16) & 0xF;

    *family = (base_family == 0xF) ? (base_family + ext_family) : base_family;
    *model  = (base_family == 0x6 || base_family == 0xF)
                ? ((ext_model << 4) | base_model)
                : base_model;
    return 1;
}

static void
collect_samples(uint64_t *samples, uint32_t count)
{
    int regs[4];
    unsigned int aux;

    // Pre-warm
    for (uint32_t i = 0; i < TIMING_PREWARM; ++i) {
        __cpuid(regs, 1);
    }

    // Measure. RDTSCP serializes; we use plain RDTSC + lfence so the
    // measured window includes only CPUID itself, matching the most common
    // detection-tool pattern (vmaware, checkhv_um).
    for (uint32_t i = 0; i < count; ++i) {
        _mm_lfence();
        uint64_t t0 = __rdtsc();
        _mm_lfence();

        __cpuid(regs, 1);

        _mm_lfence();
        uint64_t t1 = __rdtsc();
        _mm_lfence();

        samples[i] = (t1 > t0) ? (t1 - t0) : 0;
        (void)aux;
    }
}

static void
aggregate(uint64_t *samples, uint32_t count,
          uint64_t *p50, uint64_t *p99, uint64_t *max)
{
    qsort(samples, count, sizeof(uint64_t), cmp_u64);

    // Drop top 0.1% as outliers (system noise, preemption).
    uint32_t trim = count / 1000;
    uint32_t usable = (count > trim) ? (count - trim) : count;

    *p50 = samples[usable / 2];
    *p99 = samples[(usable * 99) / 100];
    *max = samples[usable - 1];
}

int
calibration_capture_baseline(timing_baseline_t *out)
{
    if (!out) return 0;

    uint64_t *samples = (uint64_t *)malloc(sizeof(uint64_t) * TIMING_SAMPLES);
    if (!samples) return 0;

    collect_samples(samples, TIMING_SAMPLES);

    memset(out, 0, sizeof(*out));
    aggregate(samples, TIMING_SAMPLES,
              &out->rdtsc_cpuid_delta_p50,
              &out->rdtsc_cpuid_delta_p99,
              &out->rdtsc_cpuid_delta_max);
    out->sample_count = TIMING_SAMPLES;
    get_cpu_brand(out->cpu_brand, sizeof(out->cpu_brand));
    get_cpu_family_model(&out->cpu_family, &out->cpu_model);

    free(samples);
    return 1;
}

static int
get_baseline_path(char *out, size_t out_size)
{
    PWSTR appdata = NULL;
    if (SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &appdata) != S_OK) {
        return 0;
    }
    // Convert to ANSI, append our subdir + filename
    char appdata_a[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, appdata, -1, appdata_a, sizeof(appdata_a), NULL, NULL);
    CoTaskMemFree(appdata);

    snprintf(out, out_size, "%s\\vgk_probe", appdata_a);
    CreateDirectoryA(out, NULL);
    snprintf(out, out_size, "%s\\vgk_probe\\baseline.json", appdata_a);
    return 1;
}

int
calibration_save_baseline(const timing_baseline_t *baseline)
{
    char path[MAX_PATH];
    if (!get_baseline_path(path, sizeof(path))) return 0;

    FILE *f = fopen(path, "w");
    if (!f) return 0;

    fprintf(f,
        "{\n"
        "  \"version\": \"%s\",\n"
        "  \"cpu_brand\": \"%s\",\n"
        "  \"cpu_family\": %u,\n"
        "  \"cpu_model\": %u,\n"
        "  \"rdtsc_cpuid_delta_p50\": %llu,\n"
        "  \"rdtsc_cpuid_delta_p99\": %llu,\n"
        "  \"rdtsc_cpuid_delta_max\": %llu,\n"
        "  \"sample_count\": %u\n"
        "}\n",
        VGK_PROBE_VERSION,
        baseline->cpu_brand,
        baseline->cpu_family,
        baseline->cpu_model,
        (unsigned long long)baseline->rdtsc_cpuid_delta_p50,
        (unsigned long long)baseline->rdtsc_cpuid_delta_p99,
        (unsigned long long)baseline->rdtsc_cpuid_delta_max,
        baseline->sample_count);

    fclose(f);
    return 1;
}

int
calibration_load_baseline(timing_baseline_t *out)
{
    char path[MAX_PATH];
    if (!get_baseline_path(path, sizeof(path))) return 0;

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    // Minimal hand-parsed JSON: we only emit a tiny known shape.
    char line[256];
    memset(out, 0, sizeof(*out));
    while (fgets(line, sizeof(line), f)) {
        sscanf(line, " \"cpu_brand\": \"%63[^\"]\"",        out->cpu_brand);
        sscanf(line, " \"cpu_family\": %u",                  &out->cpu_family);
        sscanf(line, " \"cpu_model\": %u",                   &out->cpu_model);
        sscanf(line, " \"rdtsc_cpuid_delta_p50\": %llu", (unsigned long long *)&out->rdtsc_cpuid_delta_p50);
        sscanf(line, " \"rdtsc_cpuid_delta_p99\": %llu", (unsigned long long *)&out->rdtsc_cpuid_delta_p99);
        sscanf(line, " \"rdtsc_cpuid_delta_max\": %llu", (unsigned long long *)&out->rdtsc_cpuid_delta_max);
        sscanf(line, " \"sample_count\": %u",                &out->sample_count);
    }
    fclose(f);
    return out->sample_count > 0;
}

probe_outcome_t
probe_timing_rdtsc_cpuid_delta(const timing_baseline_t *baseline)
{
    probe_outcome_t r = {
        .name = "timing_rdtsc_cpuid_delta",
        .category = "timing",
        .result = PROBE_PASS,
    };

    if (!baseline || baseline->sample_count == 0) {
        r.result = PROBE_NEEDS_CALIB;
        snprintf(r.detail, sizeof(r.detail),
                 "no baseline; run --calibrate on clean Windows first");
        return r;
    }

    uint64_t *samples = (uint64_t *)malloc(sizeof(uint64_t) * TIMING_SAMPLES);
    if (!samples) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail), "alloc failed");
        return r;
    }

    collect_samples(samples, TIMING_SAMPLES);

    uint64_t cur_p50, cur_p99, cur_max;
    aggregate(samples, TIMING_SAMPLES, &cur_p50, &cur_p99, &cur_max);
    free(samples);

    // Threshold: 3x baseline p99 = clear hypervisor presence signal.
    uint64_t threshold = baseline->rdtsc_cpuid_delta_p99 * 3;

    if (cur_p99 > threshold) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail),
                 "p99=%llu cycles vs baseline_p99=%llu (threshold=%llu) — HV cost visible",
                 (unsigned long long)cur_p99,
                 (unsigned long long)baseline->rdtsc_cpuid_delta_p99,
                 (unsigned long long)threshold);
    } else {
        snprintf(r.detail, sizeof(r.detail),
                 "p50=%llu p99=%llu (baseline p50=%llu p99=%llu)",
                 (unsigned long long)cur_p50,
                 (unsigned long long)cur_p99,
                 (unsigned long long)baseline->rdtsc_cpuid_delta_p50,
                 (unsigned long long)baseline->rdtsc_cpuid_delta_p99);
    }
    return r;
}
