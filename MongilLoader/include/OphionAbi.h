/*
 * OphionAbi.h - VMCALL ABI between cheat exe (user-mode) and Ophion VMM
 *
 * Channel:
 *   cheat_exe -> ntdll!NtCreateProfile(MAGIC_HANDLE, ...) -> ntos.text trampoline
 *   trampoline emits VMCALL with rax=session_key, rdx=op, r8=args
 *   VMM in VMX-root validates three-factor auth (image_hash + key + RIP+CR3)
 *   serves op, returns via VMRESUME
 *
 * Three-factor auth (per Grill 16):
 *   1. session_key in rax              ephemeral, exchanged at REGISTER
 *   2. caller RIP in trampoline range  ntos.text patch site
 *   3. caller CR3 = system CR3         driver-side trampoline runs in system context
 *
 * Anti-probe: any VMCALL not matching all three -> inject #UD at guest RIP,
 * timing-compensate via existing CPUID/RDTSC compensation infra so the
 * exception delay matches bare-metal #UD latency.
 */
#pragma once

#include <stdint.h>

#define OPHION_VMCALL_MAGIC_HANDLE     ((void *)0xCAFEDEADBEEF1234ULL)

// rdx selectors. session_key always in rax, args in r8 (phys addr to user buffer).

#define OPHION_OP_REGISTER             0x01
#define OPHION_OP_RESOLVE_TARGET       0x02
#define OPHION_OP_READ_MANY            0x03
#define OPHION_OP_STATUS_QUERY         0x04
#define OPHION_OP_UNREGISTER           0x05
#define OPHION_OP_SET_KERNEL_OFFSETS   0x06
#define OPHION_OP_LIST_MODULES         0x07
#define OPHION_OP_WRITE_MANY           0x08
#define OPHION_OP_LIST_PROCESSES       0x09
#define OPHION_OP_RESOLVE_TARGET_BY_PID 0x0A   // Phase 6k
#define OPHION_OP_READ_SCATTER         0x0B   // Grill Q10: gathered scatter-read

// REGISTER request layout (r8 points to this struct in caller memory)
typedef struct {
    uint8_t  image_sha256[32];     // SHA-256 of caller process .text section
    uint64_t image_base;           // caller process image base
    uint32_t image_size;
    uint32_t reserved;
} ophion_register_req_t;

typedef struct {
    uint64_t session_key;          // out: ephemeral key, use in rax for subsequent ops
    uint32_t ophion_version;       // out
    uint32_t status;               // out: 0=ok, !=0 = rejected (image hash mismatch, etc.)
} ophion_register_resp_t;

// RESOLVE_TARGET — walk PsActiveProcessHead, match EPROCESS.ImageFileName.
// Phase 5c uses RAW 16-byte name (NUL-padded, ASCII) instead of SHA-256.
// Matches EPROCESS.ImageFileName layout exactly so we can memcmp 16 bytes
// without SHA-256 in VMX-root. Anti-evasion deferred to Phase 6.
typedef struct {
    char target_name[16];          // raw bytes, NUL-padded, e.g. "explorer.exe\0\0\0\0"
} ophion_resolve_req_t;

typedef struct {
    uint32_t target_pid;           // out
    uint32_t image_size;
    uint64_t image_base;
    uint32_t status;
    uint32_t reserved;
} ophion_resolve_resp_t;

// READ_MANY: batched cross-process memory read
#define OPHION_READ_MANY_MAX_ENTRIES   64

typedef struct {
    uint64_t src_va;               // target process virtual address
    uint64_t dst_va;               // caller virtual address (validated)
    uint32_t len;
    uint32_t reserved;
} ophion_read_entry_t;

typedef struct {
    uint32_t target_pid;
    uint32_t entry_count;
    ophion_read_entry_t entries[OPHION_READ_MANY_MAX_ENTRIES];
} ophion_read_many_req_t;

typedef struct {
    uint32_t bytes_read[OPHION_READ_MANY_MAX_ENTRIES]; // 0 = walk failed
    uint32_t status;
    uint32_t reserved;
} ophion_read_many_resp_t;

// WRITE_MANY: symmetric to READ_MANY but reverse direction. Per entry:
//   src_va = caller process VA  (read source)
//   dst_va = target process VA  (write dest)
//   len    = byte count
// Reuses ophion_read_entry_t layout (sym names, reversed semantics).
#define OPHION_WRITE_MANY_MAX_ENTRIES  64
typedef ophion_read_entry_t ophion_write_entry_t;

typedef struct {
    uint32_t target_pid;
    uint32_t entry_count;
    ophion_write_entry_t entries[OPHION_WRITE_MANY_MAX_ENTRIES];
} ophion_write_many_req_t;

typedef struct {
    uint32_t bytes_written[OPHION_WRITE_MANY_MAX_ENTRIES]; // 0 = walk failed
    uint32_t status;
    uint32_t reserved;
} ophion_write_many_resp_t;

// SET_KERNEL_OFFSETS: cheat exe pushes kernel symbol VAs + EPROCESS offsets
// resolved via dbghelp + symsrv from C:\Windows\System32\ntoskrnl.exe. Used by
// RESOLVE_TARGET to walk PsActiveProcessHead doubly-linked list of EPROCESS.
typedef struct {
    uint64_t ps_active_process_head_va;     // resolved kernel VA, not RVA
    uint16_t off_active_process_links;      // EPROCESS field offsets
    uint16_t off_unique_process_id;
    uint16_t off_image_file_name;
    uint16_t off_directory_table_base;
    uint16_t off_section_base_address;
    uint16_t off_peb;
    uint32_t status;                         // out: 0=ok, !=0=rejected
    uint32_t reserved;
} ophion_kernel_offsets_t;

// LIST_MODULES: walk target PEB->Ldr->InLoadOrderModuleList, return per-module
// {basename, dll_base, image_size}. PEB pointer comes from target's
// EPROCESS.Peb (pushed via SET_KERNEL_OFFSETS earlier). PEB/Ldr field offsets
// are hardcoded Win10 19045 values in VMM; refresh if target build changes.
#define OPHION_LIST_MODULES_MAX  32

typedef struct {
    char     name[64];
    uint64_t dll_base;
    uint32_t image_size;
    uint32_t reserved;
} ophion_module_entry_t;

typedef struct {
    uint32_t target_pid;       // unused — VMM uses cached session->target_cr3
    uint32_t reserved;
} ophion_list_modules_req_t;

typedef struct {
    uint32_t module_count;
    uint32_t status;
    ophion_module_entry_t modules[OPHION_LIST_MODULES_MAX];
} ophion_list_modules_resp_t;

// RESOLVE_TARGET_BY_PID — pair op for LIST_PROCESSES result. Saves second
// PsActiveProcessHead walk when cheat already has pid from list_processes.
typedef struct {
    uint32_t target_pid;
    uint32_t reserved;
} ophion_resolve_pid_req_t;

// Reuses ophion_resolve_resp_t (target_pid, image_size, image_base, status).

// LIST_PROCESSES: walk PsActiveProcessHead, return up to 64 EPROCESS entries
// (pid, image_base, image_size, name). Useful for cheat to find target without
// knowing exact name. No request body (filtering can be added later).
#define OPHION_LIST_PROCESSES_MAX  64

typedef struct {
    uint32_t pid;
    uint32_t reserved0;
    uint64_t image_base;
    uint32_t image_size;
    char     name[16];      // EPROCESS.ImageFileName 15 bytes + NUL
    uint32_t reserved1;
} ophion_process_entry_t;

typedef struct {
    uint32_t reserved;       // request placeholder
    uint32_t reserved2;
} ophion_list_processes_req_t;

typedef struct {
    uint32_t process_count;
    uint32_t status;
    ophion_process_entry_t processes[OPHION_LIST_PROCESSES_MAX];
} ophion_list_processes_resp_t;

// STATUS_QUERY (no request body; response only)
typedef struct {
    uint32_t ophion_loaded;
    uint32_t ophion_version;
    uint32_t patch_applied;        // 1 = ntos.text trampoline installed
    uint32_t ntos_build_known;     // 1 = recognized SHA, 0 = unknown build (graceful degradation)
    uint64_t vmm_uptime_ms;
} ophion_status_resp_t;

// Status codes shared across responses
#define OPHION_STATUS_OK                   0
#define OPHION_STATUS_NOT_REGISTERED       1
#define OPHION_STATUS_IMAGE_HASH_MISMATCH  2
#define OPHION_STATUS_SESSION_INVALID      3
#define OPHION_STATUS_TARGET_NOT_FOUND     4
#define OPHION_STATUS_READ_FAILED          5
#define OPHION_STATUS_INVALID_ARG          6
#define OPHION_STATUS_WRITE_FAILED         7

// READ_SCATTER (Grill Q10): gathered scatter-read for UE4 entity walks.
// READ_MANY caps at 64 entries and scatters output to per-entry dst_va.
// READ_SCATTER caps at 1024 entries and writes to a single contiguous out
// buffer at caller-specified offsets — cache-friendly for tree traversal.
//
// Caller layout in VMCALL r8 buffer:
//   [ophion_read_scatter_req_t][ophion_read_scatter_resp_t]
// Output buffer is a SEPARATE caller VA (req.out_buf_va) — driver passes
// system VA from MDL of user buffer; VMM probes via caller_cr3.
#define OPHION_READ_SCATTER_MAX_ENTRIES  1024

typedef struct {
    uint64_t src_va;          // target process VA to read from
    uint32_t len;             // bytes; 0 < len <= 4096
    uint32_t out_offset;      // offset in out_buf_va where result lands
} ophion_scatter_entry_t;

typedef struct {
    uint32_t target_pid;      // unused — uses session->target_cr3
    uint32_t entry_count;     // 1..OPHION_READ_SCATTER_MAX_ENTRIES
    uint64_t out_buf_va;      // caller VA of gathered output buffer
    uint32_t out_buf_size;    // total bytes; bounds check for out_offset+len
    uint32_t reserved;
    ophion_scatter_entry_t entries[OPHION_READ_SCATTER_MAX_ENTRIES];
} ophion_read_scatter_req_t;

typedef struct {
    uint32_t ok_count;        // entries that read full len
    uint32_t fail_count;      // entries that returned 0 (walk failed)
    uint32_t total_bytes;     // sum of successful read lengths
    uint32_t status;          // OK if ok_count == entry_count, else READ_FAILED
} ophion_read_scatter_resp_t;
