/*
 * VmcallHandler.c - VMM-side VMCALL dispatch (Phase 4 scaffold)
 *
 * Called from VMX-root context after a guest VMCALL VMEXIT. Validates the
 * three-factor auth (image hash + session_key + RIP+CR3 binding) and
 * dispatches by op_code per OphionAbi.h.
 *
 * State at entry (set by VMEXIT handler):
 *   regs->rax = session_key (or 0 for REGISTER)
 *   regs->rdx = op_code
 *   regs->r8  = caller-buffer VA in caller process address space
 *   regs->r9  = caller-buffer size in bytes
 *
 * The caller buffer must be PT-walked from the caller's CR3 (system CR3 for
 * shim-context callers) to a VMM-mapped scratch region before reading. Phase
 * 4 work hooks this into the manual PT walker (memreader_vmx_root.c, port
 * from existing memreader.c).
 *
 * For now this file just validates op codes and returns NOT_IMPLEMENTED so
 * the dispatcher byte structure is in the binary and ready to be wired in.
 */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>
#include <intrin.h>

#include "EfiCompat.h"
#include "../include/OphionAbi.h"
#include "../include/BuildInfo.h"
#include "VmmSpin.h"
#include "VmmPerCpuLog.h"

extern UINT64 g_vmm_start_tsc;

extern UINT64 g_ps_active_process_head_va;
extern UINT16 g_off_active_process_links;
extern UINT16 g_off_unique_process_id;
extern UINT16 g_off_image_file_name;
extern UINT16 g_off_directory_table_base;
extern UINT16 g_off_section_base_address;
extern UINT16 g_off_peb;
extern UINT32 g_kernel_offsets_set;

extern UINTN  vmm_guest_read(UINT64 cr3, UINT64 va, VOID *dst, UINTN size);
extern UINTN  vmm_guest_write(UINT64 cr3, UINT64 va, CONST VOID *src, UINTN size);
extern UINT64 vmm_guest_read64(UINT64 cr3, UINT64 va);

// Phase 5f SHA-256.
typedef struct {
    UINT8  data[64];
    UINT32 datalen;
    UINT64 bitlen;
    UINT32 state[8];
} sha256_ctx;
extern VOID sha256_init(sha256_ctx *ctx);
extern VOID sha256_update(sha256_ctx *ctx, CONST UINT8 *data, UINTN len);
extern VOID sha256_final(sha256_ctx *ctx, UINT8 hash[32]);

// Compiled-in expected cheat exe .text hash. All-zero = wildcard (dev mode).
// Phase 7a: real hash baked for DispCalAgent_orgj6wkf.exe (sha256 of .text).
// Production: regenerate per-cheat-exe at MongilLoader build time.
//
// To test rejection path: any other binary's .text won't match → REGISTER
// returns IMAGE_HASH_MISMATCH. To restore dev mode: revert to all-zero.
// Compiled-in expected cheat exe .text hash. Phase 5g: locked to
// detect/ophn_resolve_probe/ophn_hash_check.exe build sha (verified via
// scripts/hash_cheat_exe.py + matched by user-mode bcrypt).
// Production build flips OPHION_DEV_ACCEPT_ALL=0 to enforce.
static CONST UINT8 kExpectedCheatHash[32] = {
    0x51, 0x78, 0xa6, 0xa4, 0x6c, 0x12, 0x22, 0x26,
    0x7e, 0x08, 0x85, 0xa7, 0x08, 0xbe, 0x5c, 0xbe,
    0x0b, 0xe6, 0x34, 0xd6, 0x70, 0x0a, 0xd9, 0x20,
    0x4c, 0x8b, 0xe5, 0x8a, 0x8a, 0xe2, 0x5c, 0xdf,
};

// Phase 5f diagnostic — last computed hash from REGISTER walk.
UINT8 g_last_register_hash[32] = {0};
UINT32 g_last_register_text_size = 0;
UINT64 g_last_register_text_va   = 0;

// Phase 5c diagnostic globals — readable via OPHR subleaf 13/14.
UINT64 g_resolve_last_cr3       = 0;
UINT64 g_resolve_first_link     = 0;
UINT32 g_resolve_iter_count     = 0;
UINT64 g_resolve_last_eproc     = 0;
UINT8  g_resolve_last_name[16]  = {0};

// i5-12400F base frequency 2.5GHz → 2.5M cycles/ms. Hardcoded for now;
// Phase 5+ should read CPUID.0x15 for TSC freq across rigs.
#define TSC_CYCLES_PER_MS  2500000ULL

// Ephemeral session table. Indexed by CR3.
#define MAX_SESSIONS  4

typedef struct {
    BOOLEAN   in_use;
    UINT64    session_key;
    UINT64    caller_cr3;
    UINT64    caller_image_base;
    UINT32    caller_image_size;
    UINT32    target_pid;          // resolved via OPHION_OP_RESOLVE_TARGET
    UINT64    target_image_base;
    UINT64    target_cr3;          // Phase 5c: cached EPROCESS.DirectoryTableBase
} ophion_session_t;

static ophion_session_t g_sessions[MAX_SESSIONS];
static UINT64           g_register_counter = 0;

// Step #8 (Grill Q20-B): per-resource spinlock. Held only during table
// mutation (allocate, register-finalize, UNREGISTER zero) so vmexit hot
// path stays lock-free in the BSP-only era. AP virt (Step #B1+) makes
// this serialize cross-CPU REGISTER/UNREGISTER races.
static VMM_SPIN g_session_lock;

// Step #8 (Grill Q20-B): per-session target-process cache lock. Resolve
// handlers mutate s->target_cr3/target_pid/target_image_base; concurrent
// READ/WRITE handlers read those fields. BSP-only era: contention zero.
// AP era: serializes RESOLVE racing in-flight READ_SCATTER on same session.
static VMM_SPIN g_proc_cache_lock;

static UINT64
random_session_key(VOID)
{
    // Combination of TSC + counter; not cryptographically strong but suffices
    // for in-VMM channel auth (attacker can't observe the key without already
    // breaking the VMM).
    UINT64 tsc = __rdtsc();
    g_register_counter++;
    return tsc ^ (g_register_counter * 0x9E3779B97F4A7C15ULL);
}

static ophion_session_t *
find_session_by_key(UINT64 key)
{
    if (key == 0) return NULL;
    for (UINTN i = 0; i < MAX_SESSIONS; ++i) {
        if (g_sessions[i].in_use && g_sessions[i].session_key == key) {
            return &g_sessions[i];
        }
    }
    return NULL;
}

static ophion_session_t *
allocate_session(VOID)
{
    for (UINTN i = 0; i < MAX_SESSIONS; ++i) {
        if (!g_sessions[i].in_use) return &g_sessions[i];
    }
    return NULL;
}

/*
 * OPHION_OP_REGISTER handler.
 *
 * Phase 4 production:
 *   1. PT-walk caller's image from caller CR3 to read .text bytes
 *   2. Compute SHA-256 over .text
 *   3. Compare against kExpectedCheatExeHash (constant-time)
 *   4. On match, allocate session, store key, return key + version
 *
 * Phase 2 stub: skip hash check, just allocate session.
 */
static UINT32
handle_register(
    IN  ophion_register_req_t  *req,
    OUT ophion_register_resp_t *resp,
    IN  UINT64                  caller_cr3
    )
{
    if (!req || !resp) return OPHION_STATUS_INVALID_ARG;

    // Phase 5f: hash caller's .text via PT walk in caller_cr3.
    // 1. Read DOS+NT header at req->image_base.
    static UINT8 hdr[0x400];
    ZeroMem(hdr, sizeof(hdr));
    if (vmm_guest_read(caller_cr3, req->image_base, hdr, sizeof(hdr)) != sizeof(hdr)) {
        resp->status = OPHION_STATUS_IMAGE_HASH_MISMATCH;
        return OPHION_STATUS_IMAGE_HASH_MISMATCH;
    }
    if (hdr[0] != 'M' || hdr[1] != 'Z') {
        resp->status = OPHION_STATUS_IMAGE_HASH_MISMATCH;
        return OPHION_STATUS_IMAGE_HASH_MISMATCH;
    }
    UINT32 e_lfanew = *(UINT32 *)&hdr[0x3C];
    if (e_lfanew == 0 || e_lfanew + 0x100 > sizeof(hdr)) {
        resp->status = OPHION_STATUS_IMAGE_HASH_MISMATCH;
        return OPHION_STATUS_IMAGE_HASH_MISMATCH;
    }
    if (*(UINT32 *)&hdr[e_lfanew] != 0x00004550) {
        resp->status = OPHION_STATUS_IMAGE_HASH_MISMATCH;
        return OPHION_STATUS_IMAGE_HASH_MISMATCH;
    }

    // 2. Walk section headers to find .text.
    UINT16 n_sections      = *(UINT16 *)&hdr[e_lfanew + 4 + 2];
    UINT16 opt_hdr_size    = *(UINT16 *)&hdr[e_lfanew + 4 + 16];
    UINT32 sect_off        = e_lfanew + 4 + 20 + opt_hdr_size;
    UINT64 text_va = 0;
    UINT32 text_size = 0;
    for (UINT16 i = 0; i < n_sections && (sect_off + i * 40 + 40) <= sizeof(hdr); i++) {
        UINT8 *s = &hdr[sect_off + i * 40];
        if (s[0] == '.' && s[1] == 't' && s[2] == 'e' && s[3] == 'x' && s[4] == 't') {
            UINT32 vsize  = *(UINT32 *)&s[8];
            UINT32 vaddr  = *(UINT32 *)&s[12];
            text_va   = req->image_base + vaddr;
            text_size = vsize;
            break;
        }
    }
    g_last_register_text_va   = text_va;
    g_last_register_text_size = text_size;

    if (text_va == 0 || text_size == 0 || text_size > 0x1000000) {
        resp->status = OPHION_STATUS_IMAGE_HASH_MISMATCH;
        return OPHION_STATUS_IMAGE_HASH_MISMATCH;
    }

    // 3. SHA-256 .text in 4KB chunks (vm_guest_read internally page-walks).
    sha256_ctx ctx;
    sha256_init(&ctx);
    static UINT8 chunk[0x1000];
    UINT32 done = 0;
    while (done < text_size) {
        UINT32 step = (text_size - done >= sizeof(chunk)) ? (UINT32)sizeof(chunk)
                                                          : (text_size - done);
        UINTN got = vmm_guest_read(caller_cr3, text_va + done, chunk, step);
        if (got == 0) break;
        sha256_update(&ctx, chunk, got);
        done += (UINT32)got;
        if (got < step) break; // unmapped page → stop
    }
    UINT8 hash[32];
    sha256_final(&ctx, hash);
    for (UINTN i = 0; i < 32; i++) g_last_register_hash[i] = hash[i];

    // 4. Compare hash to compiled-in expected. Phase 5g: locked auth.
    // Flip OPHION_DEV_ACCEPT_ALL=0 to enforce kExpectedCheatHash compare.
    // Step #4 (Grill Q5-D): dev-mode bypass — any caller .text accepted.
    // Production must flip to 0 and bake real hash via scripts/hash_cheat_exe.py.
#define OPHION_DEV_ACCEPT_ALL 1
#if !OPHION_DEV_ACCEPT_ALL
    for (UINTN i = 0; i < 32; i++) {
        if (hash[i] != kExpectedCheatHash[i]) {
            resp->status = OPHION_STATUS_IMAGE_HASH_MISMATCH;
            return OPHION_STATUS_IMAGE_HASH_MISMATCH;
        }
    }
#endif

    // 5. Allocate session. Step #8: lock around table mutation only.
    UINT64 lock_flags = VmmSpinAcquire(&g_session_lock);
    ophion_session_t *s = allocate_session();
    if (!s) {
        VmmSpinRelease(&g_session_lock, lock_flags);
        resp->status = OPHION_STATUS_NOT_REGISTERED;
        return OPHION_STATUS_NOT_REGISTERED;
    }

    s->in_use            = TRUE;
    s->session_key       = random_session_key();
    s->caller_cr3        = caller_cr3;
    s->caller_image_base = req->image_base;
    s->caller_image_size = req->image_size;
    VmmSpinRelease(&g_session_lock, lock_flags);

    resp->session_key    = s->session_key;
    resp->ophion_version = OPHION_VERSION_U32;
    resp->status         = OPHION_STATUS_OK;
    return OPHION_STATUS_OK;
}

static UINT32
handle_resolve_target(
    IN  ophion_session_t       *s,
    IN  ophion_resolve_req_t   *req,
    OUT ophion_resolve_resp_t  *resp,
    IN  UINT64                  caller_cr3
    )
{
    if (!s || !req || !resp) return OPHION_STATUS_INVALID_ARG;
    if (!g_kernel_offsets_set || g_ps_active_process_head_va == 0) {
        resp->status = OPHION_STATUS_NOT_REGISTERED;
        return OPHION_STATUS_NOT_REGISTERED;
    }

    g_resolve_last_cr3 = caller_cr3;

    UINT64 head = g_ps_active_process_head_va;
    UINT64 first_link = vmm_guest_read64(caller_cr3, head);
    g_resolve_first_link = first_link;
    if (first_link == 0 || first_link == head) {
        resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
        return OPHION_STATUS_TARGET_NOT_FOUND;
    }

    UINT64 cur = first_link;
    UINT32 iter = 0;
    while (cur != head && iter < 4096) {
        iter++;
        UINT64 eproc = cur - (UINT64)g_off_active_process_links;
        g_resolve_last_eproc = eproc;
        UINT8 name[16] = {0};
        UINTN got = vmm_guest_read(caller_cr3, eproc + g_off_image_file_name, name, 16);
        if (got == 16) {
            for (UINTN k = 0; k < 16; k++) g_resolve_last_name[k] = name[k];
            // EPROCESS.ImageFileName is UCHAR[15] on Win10 19045. Byte 15 is
            // the first byte of the next EPROCESS field — exclude from compare.
            // Also stop at first NUL in user-supplied target_name; bytes after
            // are arbitrary in EPROCESS but caller has them zeroed.
            BOOLEAN match = TRUE;
            UINTN i;
            for (i = 0; i < 15; i++) {
                UINT8 want = (UINT8)req->target_name[i];
                if (want == 0) {
                    // End of user name — require NUL or end-of-15 in EPROCESS.
                    if (i < 15 && name[i] != 0) match = FALSE;
                    break;
                }
                if (name[i] != want) { match = FALSE; break; }
            }
            if (match) {
                UINT64 pid = vmm_guest_read64(caller_cr3,
                                              eproc + g_off_unique_process_id);
                UINT64 base = vmm_guest_read64(caller_cr3,
                                              eproc + g_off_section_base_address);
                UINT64 dtb = vmm_guest_read64(caller_cr3,
                                              eproc + g_off_directory_table_base);
                resp->target_pid  = (UINT32)pid;
                resp->image_base  = base;
                resp->image_size  = 0;
                resp->reserved    = 0;
                resp->status      = OPHION_STATUS_OK;
                UINT64 pcl_flags = VmmSpinAcquire(&g_proc_cache_lock);
                s->target_pid          = (UINT32)pid;
                s->target_image_base   = base;
                s->target_cr3          = dtb;       // Phase 5d cache
                VmmSpinRelease(&g_proc_cache_lock, pcl_flags);
                g_resolve_iter_count = iter;
                return OPHION_STATUS_OK;
            }
        }
        UINT64 next = vmm_guest_read64(caller_cr3, cur);
        if (next == 0 || next == cur) break;
        cur = next;
    }
    g_resolve_iter_count = iter;
    resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
    return OPHION_STATUS_TARGET_NOT_FOUND;
}

//
// Phase 6j: enumerate active processes via PsActiveProcessHead. Returns up to
// OPHION_LIST_PROCESSES_MAX entries with {pid, image_base, image_size, name}.
//
static UINT32
handle_list_processes(
    IN  ophion_session_t              *s,
    OUT ophion_list_processes_resp_t  *resp,
    IN  UINT64                         caller_cr3
    )
{
    if (!s || !resp) return OPHION_STATUS_INVALID_ARG;
    if (!g_kernel_offsets_set || g_ps_active_process_head_va == 0) {
        resp->status = OPHION_STATUS_NOT_REGISTERED;
        return OPHION_STATUS_NOT_REGISTERED;
    }

    ZeroMem(resp->processes, sizeof(resp->processes));
    resp->process_count = 0;

    UINT64 head = g_ps_active_process_head_va;
    UINT64 cur  = vmm_guest_read64(caller_cr3, head);
    UINT32 i = 0;
    UINT32 iter = 0;
    while (cur != 0 && cur != head && iter < 4096 && i < OPHION_LIST_PROCESSES_MAX) {
        iter++;
        UINT64 eproc = cur - (UINT64)g_off_active_process_links;

        UINT64 pid  = vmm_guest_read64(caller_cr3, eproc + g_off_unique_process_id);
        UINT64 base = vmm_guest_read64(caller_cr3, eproc + g_off_section_base_address);

        UINT8 name[16] = {0};
        vmm_guest_read(caller_cr3, eproc + g_off_image_file_name, name, 15);
        name[15] = 0;  // ensure NUL term

        ophion_process_entry_t *e = &resp->processes[i];
        e->pid        = (UINT32)pid;
        e->reserved0  = 0;
        e->image_base = base;
        e->image_size = 0;
        for (UINTN k = 0; k < 16; k++) e->name[k] = (char)name[k];
        e->reserved1  = 0;
        i++;

        UINT64 next = vmm_guest_read64(caller_cr3, cur);
        if (next == 0 || next == cur) break;
        cur = next;
    }
    resp->process_count = i;
    resp->status = OPHION_STATUS_OK;
    return OPHION_STATUS_OK;
}

//
// Phase 6k: resolve by PID. Same as RESOLVE_TARGET but matches EPROCESS by
// UniqueProcessId instead of ImageFileName. Caches target_cr3 + image_base
// in session for subsequent READ/WRITE/LIST_MODULES.
//
static UINT32
handle_resolve_target_by_pid(
    IN  ophion_session_t            *s,
    IN  ophion_resolve_pid_req_t    *req,
    OUT ophion_resolve_resp_t       *resp,
    IN  UINT64                       caller_cr3
    )
{
    if (!s || !req || !resp) return OPHION_STATUS_INVALID_ARG;
    if (!g_kernel_offsets_set || g_ps_active_process_head_va == 0) {
        resp->status = OPHION_STATUS_NOT_REGISTERED;
        return OPHION_STATUS_NOT_REGISTERED;
    }
    if (req->target_pid == 0) return OPHION_STATUS_INVALID_ARG;

    UINT64 head = g_ps_active_process_head_va;
    UINT64 cur  = vmm_guest_read64(caller_cr3, head);
    UINT32 iter = 0;
    while (cur != 0 && cur != head && iter < 4096) {
        iter++;
        UINT64 eproc = cur - (UINT64)g_off_active_process_links;
        UINT64 pid = vmm_guest_read64(caller_cr3,
                                      eproc + g_off_unique_process_id);
        if ((UINT32)pid == req->target_pid) {
            UINT64 base = vmm_guest_read64(caller_cr3,
                                           eproc + g_off_section_base_address);
            UINT64 dtb  = vmm_guest_read64(caller_cr3,
                                           eproc + g_off_directory_table_base);
            resp->target_pid  = (UINT32)pid;
            resp->image_base  = base;
            resp->image_size  = 0;
            resp->reserved    = 0;
            resp->status      = OPHION_STATUS_OK;
            UINT64 pcl_flags = VmmSpinAcquire(&g_proc_cache_lock);
            s->target_pid          = (UINT32)pid;
            s->target_image_base   = base;
            s->target_cr3          = dtb;
            VmmSpinRelease(&g_proc_cache_lock, pcl_flags);
            return OPHION_STATUS_OK;
        }
        UINT64 next = vmm_guest_read64(caller_cr3, cur);
        if (next == 0 || next == cur) break;
        cur = next;
    }
    resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
    return OPHION_STATUS_TARGET_NOT_FOUND;
}

static UINT32
handle_read_many(
    IN  ophion_session_t        *s,
    IN  ophion_read_many_req_t  *req,
    OUT ophion_read_many_resp_t *resp,
    IN  UINT64                   caller_cr3
    )
{
    if (!s || !req || !resp) return OPHION_STATUS_INVALID_ARG;
    if (req->entry_count == 0) return OPHION_STATUS_INVALID_ARG;
    if (req->entry_count > OPHION_READ_MANY_MAX_ENTRIES) return OPHION_STATUS_INVALID_ARG;
    if (s->target_cr3 == 0) {
        resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
        return OPHION_STATUS_TARGET_NOT_FOUND;
    }

    static UINT8 io_scratch[0x1000];

    ZeroMem(resp->bytes_read, sizeof(resp->bytes_read));
    UINT32 ok_count = 0;
    for (UINT32 i = 0; i < req->entry_count; i++) {
        UINT64 src = req->entries[i].src_va;
        UINT64 dst = req->entries[i].dst_va;
        UINT32 len = req->entries[i].len;
        if (len == 0 || len > sizeof(io_scratch)) continue;

        UINTN got = vmm_guest_read(s->target_cr3, src, io_scratch, len);
        if (got != len) continue;
        UINTN put = vmm_guest_write(caller_cr3, dst, io_scratch, len);
        if (put != len) continue;
        resp->bytes_read[i] = len;
        ok_count++;
    }
    resp->status = (ok_count == req->entry_count) ? OPHION_STATUS_OK
                                                  : OPHION_STATUS_READ_FAILED;
    return resp->status;
}

//
// Grill Q10: READ_SCATTER — gathered batched read for UE4 entity walks.
// Same per-page read primitive as READ_MANY but writes results into a single
// contiguous caller out buffer at caller-specified offsets, with 1024-entry
// cap (vs READ_MANY's 64). Out buffer is a separate caller VA (out_buf_va);
// driver provides system VA from MDL of user-mode gather buffer.
//
static UINT32
handle_read_scatter(
    IN  ophion_session_t            *s,
    IN  ophion_read_scatter_req_t   *req,
    OUT ophion_read_scatter_resp_t  *resp,
    IN  UINT64                       caller_cr3
    )
{
    if (!s || !req || !resp) return OPHION_STATUS_INVALID_ARG;
    if (req->entry_count == 0) return OPHION_STATUS_INVALID_ARG;
    if (req->entry_count > OPHION_READ_SCATTER_MAX_ENTRIES) return OPHION_STATUS_INVALID_ARG;
    if (req->out_buf_va == 0 || req->out_buf_size == 0) return OPHION_STATUS_INVALID_ARG;
    if (s->target_cr3 == 0) {
        resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
        return OPHION_STATUS_TARGET_NOT_FOUND;
    }

    static UINT8 sc_scratch[0x1000];

    UINT32 ok = 0, total = 0;
    for (UINT32 i = 0; i < req->entry_count; i++) {
        UINT64 src        = req->entries[i].src_va;
        UINT32 len        = req->entries[i].len;
        UINT32 out_off    = req->entries[i].out_offset;

        if (len == 0 || len > sizeof(sc_scratch)) continue;
        if ((UINT64)out_off + (UINT64)len > (UINT64)req->out_buf_size) continue;

        UINTN got = vmm_guest_read(s->target_cr3, src, sc_scratch, len);
        if (got != len) continue;
        UINTN put = vmm_guest_write(caller_cr3, req->out_buf_va + out_off,
                                    sc_scratch, len);
        if (put != len) continue;

        ok++;
        total += len;
    }

    resp->ok_count   = ok;
    resp->fail_count = req->entry_count - ok;
    resp->total_bytes = total;
    resp->status = (ok == req->entry_count) ? OPHION_STATUS_OK
                                            : OPHION_STATUS_READ_FAILED;
    return resp->status;
}

//
// Phase 6d: cross-CR3 batched write. Symmetric to READ_MANY but src/dst CR3
// flipped: read from caller, write to target.
//
static UINT32
handle_write_many(
    IN  ophion_session_t          *s,
    IN  ophion_write_many_req_t   *req,
    OUT ophion_write_many_resp_t  *resp,
    IN  UINT64                     caller_cr3
    )
{
    if (!s || !req || !resp) return OPHION_STATUS_INVALID_ARG;
    if (req->entry_count == 0) return OPHION_STATUS_INVALID_ARG;
    if (req->entry_count > OPHION_WRITE_MANY_MAX_ENTRIES) return OPHION_STATUS_INVALID_ARG;
    if (s->target_cr3 == 0) {
        resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
        return OPHION_STATUS_TARGET_NOT_FOUND;
    }

    static UINT8 wio_scratch[0x1000];

    ZeroMem(resp->bytes_written, sizeof(resp->bytes_written));
    UINT32 ok_count = 0;
    for (UINT32 i = 0; i < req->entry_count; i++) {
        UINT64 src = req->entries[i].src_va;
        UINT64 dst = req->entries[i].dst_va;
        UINT32 len = req->entries[i].len;
        if (len == 0 || len > sizeof(wio_scratch)) continue;

        UINTN got = vmm_guest_read(caller_cr3, src, wio_scratch, len);
        if (got != len) continue;
        UINTN put = vmm_guest_write(s->target_cr3, dst, wio_scratch, len);
        if (put != len) continue;
        resp->bytes_written[i] = len;
        ok_count++;
    }
    resp->status = (ok_count == req->entry_count) ? OPHION_STATUS_OK
                                                  : OPHION_STATUS_WRITE_FAILED;
    return resp->status;
}

//
// Phase 6b: walk target process PEB->Ldr->InLoadOrderModuleList. Returns up
// to OPHION_LIST_MODULES_MAX modules with basename + dll_base + image_size.
//
// Reads target_cr3 from session (set by RESOLVE_TARGET). PEB VA from
// EPROCESS.Peb (we cached EPROCESS in session via target_image_base — but
// we need EPROCESS pointer too). Quick fix: walk PsActiveProcessHead again
// to find EPROCESS by PID, read Peb field.
//
// Win10 19045 LDR offsets (stable across LCUs):
//   PEB.Ldr                                 = 0x18
//   PEB_LDR_DATA.InLoadOrderModuleList      = 0x10  (LIST_ENTRY)
//   LDR_DATA_TABLE_ENTRY.InLoadOrderLinks   = 0x00  (LIST_ENTRY)
//   LDR_DATA_TABLE_ENTRY.DllBase            = 0x30
//   LDR_DATA_TABLE_ENTRY.SizeOfImage        = 0x40
//   LDR_DATA_TABLE_ENTRY.BaseDllName        = 0x58  (UNICODE_STRING{Length, MaxLen, Buffer})
//
#define LDR_OFF_PEB_LDR                  0x18
#define LDR_OFF_INLOADORDERMODULELIST    0x10
#define LDR_OFF_DLLBASE                  0x30
#define LDR_OFF_SIZEOFIMAGE              0x40
#define LDR_OFF_BASEDLLNAME              0x58

static UINT64
find_eproc_by_pid(UINT64 caller_cr3, UINT32 target_pid)
{
    if (g_ps_active_process_head_va == 0) return 0;
    UINT64 head = g_ps_active_process_head_va;
    UINT64 cur  = vmm_guest_read64(caller_cr3, head);
    UINT32 iter = 0;
    while (cur != head && iter < 4096) {
        iter++;
        UINT64 eproc = cur - (UINT64)g_off_active_process_links;
        UINT64 pid = vmm_guest_read64(caller_cr3, eproc + g_off_unique_process_id);
        if ((UINT32)pid == target_pid) return eproc;
        UINT64 next = vmm_guest_read64(caller_cr3, cur);
        if (next == 0 || next == cur) break;
        cur = next;
    }
    return 0;
}

static UINT32
handle_list_modules(
    IN  ophion_session_t           *s,
    IN  ophion_list_modules_req_t  *req,
    OUT ophion_list_modules_resp_t *resp,
    IN  UINT64                      caller_cr3
    )
{
    if (!s || !req || !resp) return OPHION_STATUS_INVALID_ARG;
    if (s->target_cr3 == 0 || s->target_pid == 0) {
        resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
        return OPHION_STATUS_TARGET_NOT_FOUND;
    }
    if (!g_kernel_offsets_set || g_off_peb == 0) {
        resp->status = OPHION_STATUS_NOT_REGISTERED;
        return OPHION_STATUS_NOT_REGISTERED;
    }

    ZeroMem(resp->modules, sizeof(resp->modules));
    resp->module_count = 0;

    // Find EPROCESS again to read .Peb field. We cached only target_pid +
    // image_base + cr3 in session; could pre-cache eproc VA for cheaper walk.
    UINT64 eproc = find_eproc_by_pid(caller_cr3, s->target_pid);
    if (eproc == 0) {
        resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
        return OPHION_STATUS_TARGET_NOT_FOUND;
    }

    UINT64 peb = vmm_guest_read64(caller_cr3, eproc + g_off_peb);
    if (peb == 0) {
        resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
        return OPHION_STATUS_TARGET_NOT_FOUND;
    }

    // PEB lives in TARGET process VA space; switch to target_cr3 for reads.
    UINT64 ldr = vmm_guest_read64(s->target_cr3, peb + LDR_OFF_PEB_LDR);
    if (ldr == 0) {
        resp->status = OPHION_STATUS_TARGET_NOT_FOUND;
        return OPHION_STATUS_TARGET_NOT_FOUND;
    }

    UINT64 head = ldr + LDR_OFF_INLOADORDERMODULELIST;
    UINT64 cur  = vmm_guest_read64(s->target_cr3, head);  // head.Flink
    UINT32 i = 0;
    while (cur != 0 && cur != head && i < OPHION_LIST_MODULES_MAX) {
        // cur points at LDR_DATA_TABLE_ENTRY.InLoadOrderLinks (offset 0).
        UINT64 entry = cur;
        UINT64 dll_base = vmm_guest_read64(s->target_cr3, entry + LDR_OFF_DLLBASE);
        UINT32 sz       = (UINT32)vmm_guest_read64(s->target_cr3, entry + LDR_OFF_SIZEOFIMAGE);
        // BaseDllName.Length (USHORT) + MaximumLength (USHORT) + Buffer (PWSTR)
        UINT16 name_len = 0;
        vmm_guest_read(s->target_cr3, entry + LDR_OFF_BASEDLLNAME, &name_len, 2);
        UINT64 name_buf = vmm_guest_read64(s->target_cr3, entry + LDR_OFF_BASEDLLNAME + 8);

        if (dll_base != 0 && name_buf != 0) {
            UINT16 wbytes[64];
            ZeroMem(wbytes, sizeof(wbytes));
            UINT32 to_read = (name_len < (UINT32)sizeof(wbytes)) ? name_len : (UINT32)sizeof(wbytes);
            vmm_guest_read(s->target_cr3, name_buf, wbytes, to_read);

            // UTF-16 → ASCII (drop high byte).
            ophion_module_entry_t *m = &resp->modules[i];
            UINT32 chars = to_read / 2;
            UINT32 j;
            for (j = 0; j < chars && j < sizeof(m->name) - 1; j++) {
                UINT16 c = wbytes[j];
                m->name[j] = (c < 0x80) ? (char)c : '?';
            }
            m->name[j] = '\0';
            m->dll_base   = dll_base;
            m->image_size = sz;
            m->reserved   = 0;
            i++;
        }

        UINT64 next = vmm_guest_read64(s->target_cr3, cur);
        if (next == 0 || next == cur) break;
        cur = next;
    }
    resp->module_count = i;
    resp->status = OPHION_STATUS_OK;
    return OPHION_STATUS_OK;
}

//
// Step #8 (Grill Q21-C): drain VMM per-CPU vmexit log into caller's pool.
// Caller is expected to be the Ophion driver running in system context;
// caller_cr3 == system_cr3 so vmm_guest_write resolves out_buf_va via the
// driver's pool mapping. Magic + per-CPU layout described in OphionAbi.h.
//
static UINT32
handle_get_percpu_log(
    IN  ophion_session_t                 *s,
    IN  ophion_get_percpu_log_req_t      *req,
    OUT ophion_get_percpu_log_resp_t     *resp,
    IN  UINT64                            caller_cr3
    )
{
    if (!s || !req || !resp) return OPHION_STATUS_INVALID_ARG;

    resp->magic           = 0;
    resp->bytes_written   = 0;
    resp->cpu_count       = 0;
    resp->records_per_cpu = 0;

    if (req->out_buf_va == 0 || req->out_buf_size == 0) {
        resp->status = OPHION_STATUS_INVALID_ARG;
        return OPHION_STATUS_INVALID_ARG;
    }

    UINTN need = VmmPclRequiredSize();
    if (need == 0) {
        resp->status = OPHION_STATUS_NOT_REGISTERED;
        return OPHION_STATUS_NOT_REGISTERED;
    }
    if (need > req->out_buf_size) {
        resp->status = OPHION_STATUS_INVALID_ARG;
        return OPHION_STATUS_INVALID_ARG;
    }

    // Static scratch sized to the 12-thread Alder Lake target plus headroom
    // (24 cores * 1032 + 16 = 24784 < 32768). Avoids large stack frames in
    // VMX-root context where the host stack is small.
    static UINT8 sn_scratch[32768];
    if (need > sizeof(sn_scratch)) {
        resp->status = OPHION_STATUS_INVALID_ARG;
        return OPHION_STATUS_INVALID_ARG;
    }
    UINTN got = VmmPclSnapshot(sn_scratch, sizeof(sn_scratch));
    if (got == 0 || got != need) {
        resp->status = OPHION_STATUS_READ_FAILED;
        return OPHION_STATUS_READ_FAILED;
    }

    UINTN put = vmm_guest_write(caller_cr3, req->out_buf_va, sn_scratch, got);
    if (put != got) {
        resp->status = OPHION_STATUS_WRITE_FAILED;
        return OPHION_STATUS_WRITE_FAILED;
    }

    // Snapshot blob layout: [magic u64][cpu_count u32][rec_per_cpu u32]...
    resp->magic           = VMM_PCL_MAGIC;
    resp->bytes_written   = (UINT32)got;
    resp->cpu_count       = *(UINT32 *)(sn_scratch + sizeof(UINT64));
    resp->records_per_cpu = VMM_PCL_RECORDS_PER_CPU;
    resp->status          = OPHION_STATUS_OK;
    return OPHION_STATUS_OK;
}

static UINT32
handle_status_query(
    OUT ophion_status_resp_t *resp
    )
{
    if (!resp) return OPHION_STATUS_INVALID_ARG;
    resp->ophion_loaded     = 1;
    resp->ophion_version    = OPHION_VERSION_U32;
    resp->patch_applied     = 0;     // Phase 5: read from install module
    resp->ntos_build_known  = 1;
    // Phase 5a: TSC delta from g_vmm_start_tsc (set lazily on first vmexit).
    UINT64 now = __rdtsc();
    UINT64 delta = (g_vmm_start_tsc != 0 && now > g_vmm_start_tsc)
                 ? (now - g_vmm_start_tsc) : 0;
    resp->vmm_uptime_ms = delta / TSC_CYCLES_PER_MS;
    return OPHION_STATUS_OK;
}

//
// Phase 5b: cheat user-mode pushes kernel offsets. Validates non-zero +
// kernel-space VA on PsActiveProcessHead, then latches to globals.
//
static UINT32
handle_set_kernel_offsets(
    IN OUT ophion_kernel_offsets_t *req
    )
{
    if (!req) return OPHION_STATUS_INVALID_ARG;
    if (req->ps_active_process_head_va < 0xFFFF000000000000ULL) {
        req->status = OPHION_STATUS_INVALID_ARG;
        return OPHION_STATUS_INVALID_ARG;
    }
    if (req->off_active_process_links == 0 ||
        req->off_unique_process_id    == 0 ||
        req->off_image_file_name      == 0 ||
        req->off_directory_table_base == 0 ||
        req->off_section_base_address == 0) {
        req->status = OPHION_STATUS_INVALID_ARG;
        return OPHION_STATUS_INVALID_ARG;
    }
    g_ps_active_process_head_va = req->ps_active_process_head_va;
    g_off_active_process_links  = req->off_active_process_links;
    g_off_unique_process_id     = req->off_unique_process_id;
    g_off_image_file_name       = req->off_image_file_name;
    g_off_directory_table_base  = req->off_directory_table_base;
    g_off_section_base_address  = req->off_section_base_address;
    g_off_peb                   = req->off_peb;
    g_kernel_offsets_set        = 1;
    req->status                 = OPHION_STATUS_OK;
    return OPHION_STATUS_OK;
}

/*
 * Top-level dispatch. Called from vmexit_handle_vmcall once the VMEXIT
 * handler has read RAX/RDX/R8/R9 from guest GPRs and PT-walked the caller
 * buffer into VMM-accessible scratch.
 *
 * Returns: OPHION_STATUS_* for the guest to receive in RAX after VMRESUME.
 */
UINT32
VmcallDispatch(
    IN  UINT64  session_key_in_rax,
    IN  UINT32  op_code_in_rdx,
    IN  VOID   *caller_buf,             // VMM-mapped view of caller's r8 buffer
    IN  UINT32  caller_buf_size,
    IN  UINT64  caller_rip,
    IN  UINT64  caller_cr3
    )
{
    // Three-factor auth pre-screen:
    //
    //   1. session_key (rax) authoritative for non-REGISTER ops
    //   2. caller_rip must be in the trampoline range (set at NtosPatch install)
    //   3. caller_cr3 must equal system_cr3 (kernel-context VMCALL only)
    //
    // RIP and CR3 checks are Phase 4 work; placeholder accepts any CR3.
    (VOID)caller_rip;
    (VOID)caller_cr3;

    if (op_code_in_rdx == OPHION_OP_REGISTER) {
        if (caller_buf_size < (sizeof(ophion_register_req_t) +
                               sizeof(ophion_register_resp_t)))
            return OPHION_STATUS_INVALID_ARG;
        ophion_register_req_t  *req = (ophion_register_req_t  *)caller_buf;
        ophion_register_resp_t *resp = (ophion_register_resp_t *)
            ((UINT8 *)caller_buf + sizeof(ophion_register_req_t));
        return handle_register(req, resp, caller_cr3);
    }

    ophion_session_t *s = find_session_by_key(session_key_in_rax);
    if (!s) return OPHION_STATUS_SESSION_INVALID;

    switch (op_code_in_rdx) {
    case OPHION_OP_RESOLVE_TARGET: {
        if (caller_buf_size < (sizeof(ophion_resolve_req_t) +
                               sizeof(ophion_resolve_resp_t)))
            return OPHION_STATUS_INVALID_ARG;
        ophion_resolve_req_t  *req  = (ophion_resolve_req_t  *)caller_buf;
        ophion_resolve_resp_t *resp = (ophion_resolve_resp_t *)
            ((UINT8 *)caller_buf + sizeof(ophion_resolve_req_t));
        return handle_resolve_target(s, req, resp, caller_cr3);
    }
    case OPHION_OP_READ_MANY: {
        if (caller_buf_size < (sizeof(ophion_read_many_req_t) +
                               sizeof(ophion_read_many_resp_t)))
            return OPHION_STATUS_INVALID_ARG;
        ophion_read_many_req_t  *req  = (ophion_read_many_req_t  *)caller_buf;
        ophion_read_many_resp_t *resp = (ophion_read_many_resp_t *)
            ((UINT8 *)caller_buf + sizeof(ophion_read_many_req_t));
        return handle_read_many(s, req, resp, caller_cr3);
    }
    case OPHION_OP_READ_SCATTER: {
        if (caller_buf_size < (sizeof(ophion_read_scatter_req_t) +
                               sizeof(ophion_read_scatter_resp_t)))
            return OPHION_STATUS_INVALID_ARG;
        ophion_read_scatter_req_t  *req  = (ophion_read_scatter_req_t  *)caller_buf;
        ophion_read_scatter_resp_t *resp = (ophion_read_scatter_resp_t *)
            ((UINT8 *)caller_buf + sizeof(ophion_read_scatter_req_t));
        return handle_read_scatter(s, req, resp, caller_cr3);
    }
    case OPHION_OP_LIST_MODULES: {
        if (caller_buf_size < (sizeof(ophion_list_modules_req_t) +
                               sizeof(ophion_list_modules_resp_t)))
            return OPHION_STATUS_INVALID_ARG;
        ophion_list_modules_req_t  *req  = (ophion_list_modules_req_t  *)caller_buf;
        ophion_list_modules_resp_t *resp = (ophion_list_modules_resp_t *)
            ((UINT8 *)caller_buf + sizeof(ophion_list_modules_req_t));
        return handle_list_modules(s, req, resp, caller_cr3);
    }
    case OPHION_OP_LIST_PROCESSES: {
        if (caller_buf_size < (sizeof(ophion_list_processes_req_t) +
                               sizeof(ophion_list_processes_resp_t)))
            return OPHION_STATUS_INVALID_ARG;
        ophion_list_processes_resp_t *resp = (ophion_list_processes_resp_t *)
            ((UINT8 *)caller_buf + sizeof(ophion_list_processes_req_t));
        return handle_list_processes(s, resp, caller_cr3);
    }
    case OPHION_OP_RESOLVE_TARGET_BY_PID: {
        if (caller_buf_size < (sizeof(ophion_resolve_pid_req_t) +
                               sizeof(ophion_resolve_resp_t)))
            return OPHION_STATUS_INVALID_ARG;
        ophion_resolve_pid_req_t *req = (ophion_resolve_pid_req_t *)caller_buf;
        ophion_resolve_resp_t   *resp = (ophion_resolve_resp_t *)
            ((UINT8 *)caller_buf + sizeof(ophion_resolve_pid_req_t));
        return handle_resolve_target_by_pid(s, req, resp, caller_cr3);
    }
    case OPHION_OP_WRITE_MANY: {
        if (caller_buf_size < (sizeof(ophion_write_many_req_t) +
                               sizeof(ophion_write_many_resp_t)))
            return OPHION_STATUS_INVALID_ARG;
        ophion_write_many_req_t  *req  = (ophion_write_many_req_t  *)caller_buf;
        ophion_write_many_resp_t *resp = (ophion_write_many_resp_t *)
            ((UINT8 *)caller_buf + sizeof(ophion_write_many_req_t));
        return handle_write_many(s, req, resp, caller_cr3);
    }
    case OPHION_OP_STATUS_QUERY: {
        if (caller_buf_size < sizeof(ophion_status_resp_t))
            return OPHION_STATUS_INVALID_ARG;
        return handle_status_query((ophion_status_resp_t *)caller_buf);
    }
    case OPHION_OP_SET_KERNEL_OFFSETS: {
        if (caller_buf_size < sizeof(ophion_kernel_offsets_t))
            return OPHION_STATUS_INVALID_ARG;
        return handle_set_kernel_offsets((ophion_kernel_offsets_t *)caller_buf);
    }
    case OPHION_OP_GET_PERCPU_LOG: {
        if (caller_buf_size < (sizeof(ophion_get_percpu_log_req_t) +
                               sizeof(ophion_get_percpu_log_resp_t)))
            return OPHION_STATUS_INVALID_ARG;
        ophion_get_percpu_log_req_t  *req  =
            (ophion_get_percpu_log_req_t  *)caller_buf;
        ophion_get_percpu_log_resp_t *resp =
            (ophion_get_percpu_log_resp_t *)
            ((UINT8 *)caller_buf + sizeof(ophion_get_percpu_log_req_t));
        return handle_get_percpu_log(s, req, resp, caller_cr3);
    }
    case OPHION_OP_UNREGISTER: {
        UINT64 unreg_flags = VmmSpinAcquire(&g_session_lock);
        ZeroMem(s, sizeof(*s));
        VmmSpinRelease(&g_session_lock, unreg_flags);
        return OPHION_STATUS_OK;
    }
    default:
        return OPHION_STATUS_INVALID_ARG;
    }
}
