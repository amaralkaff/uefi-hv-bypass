/*
 * nic_smbios_checks.c - NIC OUI + SMBIOS / DMI fingerprint probes
 *
 * vgk_emu.c table kOuiTable + kHvSignatures gates rejection by MAC prefix
 * and DMI vendor strings. Probes confirm bench HW does not carry any of
 * the watched values that Vanguard treats as VM evidence.
 */
#include "vgk_probe.h"
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib")

// Subset of vgk kOuiTable that any real consumer NIC would never carry.
static const struct {
    uint8_t a, b, c;
    const char *label;
} kBannedOuis[] = {
    { 0x00, 0x05, 0x69, "VMware (00:05:69)"        },
    { 0x00, 0x0C, 0x29, "VMware (00:0C:29)"        },
    { 0x00, 0x1C, 0x14, "VMware (00:1C:14)"        },
    { 0x00, 0x50, 0x56, "VMware (00:50:56)"        },
    { 0x08, 0x00, 0x27, "VirtualBox (08:00:27)"    },
    { 0x0A, 0x00, 0x27, "VirtualBox alt (0A:00:27)"},
    { 0x00, 0x15, 0x5D, "Hyper-V (00:15:5D)"       },
    { 0x00, 0x03, 0xFF, "MS Virtual PC (00:03:FF)" },
    { 0x00, 0x1C, 0x42, "Parallels (00:1C:42)"     },
    { 0x00, 0x16, 0x3E, "Xen (00:16:3E)"           },
    { 0x52, 0x54, 0x00, "QEMU/KVM (52:54:00)"      },
    { 0x52, 0x54, 0x14, "QEMU alt (52:54:14)"      },
    { 0x00, 0x21, 0xF6, "Oracle VirtualIron"       },
};

probe_outcome_t
probe_nic_mac_oui(void)
{
    probe_outcome_t r = {
        .name = "nic_mac_oui_not_banned",
        .category = "nic",
        .result = PROBE_PASS,
    };

    ULONG buf_size = 16384;
    IP_ADAPTER_ADDRESSES *adapters = (IP_ADAPTER_ADDRESSES *)malloc(buf_size);
    if (!adapters) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail), "alloc failed");
        return r;
    }

    DWORD ret = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
        NULL, adapters, &buf_size);
    if (ret != ERROR_SUCCESS) {
        free(adapters);
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail),
                 "GetAdaptersAddresses=%lu", ret);
        return r;
    }

    char hit_detail[256] = {0};
    int hit = 0;

    for (IP_ADAPTER_ADDRESSES *a = adapters; a; a = a->Next) {
        if (a->IfType != IF_TYPE_ETHERNET_CSMACD &&
            a->IfType != IF_TYPE_IEEE80211) continue;
        if (a->PhysicalAddressLength != 6) continue;
        if (a->OperStatus != IfOperStatusUp) continue;

        uint8_t oui_a = a->PhysicalAddress[0];
        uint8_t oui_b = a->PhysicalAddress[1];
        uint8_t oui_c = a->PhysicalAddress[2];

        for (size_t i = 0; i < sizeof(kBannedOuis)/sizeof(kBannedOuis[0]); ++i) {
            if (oui_a == kBannedOuis[i].a &&
                oui_b == kBannedOuis[i].b &&
                oui_c == kBannedOuis[i].c) {
                snprintf(hit_detail, sizeof(hit_detail),
                         "adapter MAC %02X:%02X:%02X:* matches %s",
                         oui_a, oui_b, oui_c, kBannedOuis[i].label);
                hit = 1;
                break;
            }
        }
        if (hit) break;
    }

    free(adapters);

    if (hit) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail), "%s", hit_detail);
    } else {
        snprintf(r.detail, sizeof(r.detail), "no banned OUI present");
    }
    return r;
}

// SMBIOS read via GetSystemFirmwareTable. Type 1 (system) = UUID at offset 8.
typedef struct {
    BYTE type;
    BYTE length;
    WORD handle;
    BYTE manufacturer;  // string index
    BYTE product;
    BYTE version;
    BYTE serial;
    BYTE uuid[16];
    BYTE wake_up_type;
    // string table follows
} smbios_type1_t;

static int
get_smbios_table(uint8_t **out_buf, uint32_t *out_size)
{
    UINT size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (size == 0) return 0;
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return 0;
    if (GetSystemFirmwareTable('RSMB', 0, buf, size) != size) {
        free(buf);
        return 0;
    }
    *out_buf = buf;
    *out_size = size;
    return 1;
}

// Skip the 8-byte RSMB header, parse SMBIOS structures until type 1 found.
static const smbios_type1_t *
find_type1(const uint8_t *table, uint32_t total_size)
{
    if (total_size < 8) return NULL;
    const uint8_t *p = table + 8;
    const uint8_t *end = table + total_size;

    while (p < end) {
        if (p + 4 > end) break;
        BYTE type = p[0];
        BYTE length = p[1];
        if (length < 4 || p + length > end) break;

        if (type == 1) return (const smbios_type1_t *)p;

        // Skip formatted area + string table (terminated by double-null).
        p += length;
        while (p < end - 1 && !(p[0] == 0 && p[1] == 0)) ++p;
        p += 2;
    }
    return NULL;
}

probe_outcome_t
probe_smbios_uuid_wellformed(void)
{
    probe_outcome_t r = {
        .name = "smbios_uuid_wellformed",
        .category = "smbios",
        .result = PROBE_PASS,
    };

    uint8_t *table = NULL;
    uint32_t size = 0;
    if (!get_smbios_table(&table, &size)) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail), "GetSystemFirmwareTable(RSMB) failed");
        return r;
    }

    const smbios_type1_t *t1 = find_type1(table, size);
    if (!t1) {
        free(table);
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail), "SMBIOS type 1 not found");
        return r;
    }

    int all_zero = 1, all_ff = 1;
    for (int i = 0; i < 16; ++i) {
        if (t1->uuid[i] != 0x00) all_zero = 0;
        if (t1->uuid[i] != 0xFF) all_ff = 0;
    }

    if (all_zero || all_ff) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail),
                 "SMBIOS UUID trivial (%s) — vgk flags as VM/spoofed",
                 all_zero ? "all-zeros" : "all-FFs");
    } else {
        snprintf(r.detail, sizeof(r.detail),
                 "UUID = %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                 t1->uuid[3], t1->uuid[2], t1->uuid[1], t1->uuid[0],
                 t1->uuid[5], t1->uuid[4], t1->uuid[7], t1->uuid[6],
                 t1->uuid[8], t1->uuid[9],
                 t1->uuid[10], t1->uuid[11], t1->uuid[12],
                 t1->uuid[13], t1->uuid[14], t1->uuid[15]);
    }
    free(table);
    return r;
}

static int
strstr_ci(const char *hay, const char *needle)
{
    size_t hlen = strlen(hay), nlen = strlen(needle);
    if (nlen > hlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; ++i) {
        size_t k;
        for (k = 0; k < nlen; ++k) {
            char a = hay[i + k]; if (a >= 'A' && a <= 'Z') a += 32;
            char b = needle[k];  if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (k == nlen) return 1;
    }
    return 0;
}

probe_outcome_t
probe_smbios_vendor_strings(void)
{
    probe_outcome_t r = {
        .name = "smbios_vendor_strings",
        .category = "smbios",
        .result = PROBE_PASS,
    };

    uint8_t *table = NULL;
    uint32_t size = 0;
    if (!get_smbios_table(&table, &size)) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail), "GetSystemFirmwareTable(RSMB) failed");
        return r;
    }

    // Search entire SMBIOS table for banned vendor substrings.
    static const char *banned[] = {
        "QEMU", "innotek", "VirtualBox", "VMware", "Xen",
        "Microsoft Corporation Virtual",  // Hyper-V system manufacturer
        "Parallels", "Bochs", "KVM"
    };

    // Walk all strings in the table region (best-effort).
    char hit[64] = {0};
    for (uint32_t i = 0; i < size; ++i) {
        if (table[i] < 0x20 || table[i] > 0x7E) continue;
        // Found ASCII char; treat as start of string, scan up to 64 bytes
        char buf[65];
        uint32_t k = 0;
        for (; k < 64 && i + k < size; ++k) {
            uint8_t c = table[i + k];
            if (c == 0 || c < 0x20 || c > 0x7E) break;
            buf[k] = (char)c;
        }
        buf[k] = 0;
        i += k;

        for (size_t b = 0; b < sizeof(banned)/sizeof(banned[0]); ++b) {
            if (strstr_ci(buf, banned[b])) {
                snprintf(hit, sizeof(hit), "%s found ('%s')", banned[b], buf);
                goto done;
            }
        }
    }
done:
    free(table);

    if (hit[0]) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail), "%s", hit);
    } else {
        snprintf(r.detail, sizeof(r.detail), "no banned vendor strings");
    }
    return r;
}

probe_outcome_t
probe_topology_processor_count(void)
{
    probe_outcome_t r = {
        .name = "topology_processor_count",
        .category = "topology",
        .result = PROBE_PASS,
    };

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    // Detection tools flag low-core VMs (1 or 2 cores). Real consumer Intel/AMD
    // chips have >= 4 cores. Single-core is QEMU default for some configs.
    if (si.dwNumberOfProcessors < 4) {
        r.result = PROBE_FAIL;
        snprintf(r.detail, sizeof(r.detail),
                 "only %lu logical CPUs (vgk heuristic: <4 = likely VM)",
                 si.dwNumberOfProcessors);
    } else {
        snprintf(r.detail, sizeof(r.detail),
                 "%lu logical CPUs", si.dwNumberOfProcessors);
    }
    return r;
}

probe_outcome_t
probe_topology_apic_consistency(void)
{
    probe_outcome_t r = {
        .name = "topology_apic_consistency",
        .category = "topology",
        .result = PROBE_PASS,
    };

    // CPUID 0xB sub-leaf 0 returns APIC topology. Bare metal returns
    // valid x2APIC IDs; many VMs return 0 for all fields.
    int regs[4];
    __cpuidex(regs, 0xB, 0);
    if (regs[0] == 0 && regs[1] == 0 && regs[2] == 0) {
        // CPUID 0xB not present; try 4 (legacy).
        __cpuidex(regs, 4, 0);
        if (regs[0] == 0) {
            r.result = PROBE_FAIL;
            snprintf(r.detail, sizeof(r.detail),
                     "no APIC topology info (CPUID 0xB and 0x4 both zero)");
            return r;
        }
    }
    snprintf(r.detail, sizeof(r.detail), "APIC topology present");
    return r;
}
