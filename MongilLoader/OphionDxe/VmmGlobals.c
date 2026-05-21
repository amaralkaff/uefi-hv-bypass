/*
 * VmmGlobals.c - global VMM state for UEFI port.
 *
 * Mirrors Ophion/src/globals.c but strips:
 *   - g_msr_bitmap_invalid (stealth feature, deferred)
 *   - g_stealth_enabled / g_stealth_cpuid_cache (deferred to post-Phase-2.5)
 *   - g_xhook (Phase 4 EPT hook, deferred)
 */
#include "EfiCompat.h"
#include "ia32.h"
#include "hv_types.h"

VIRTUAL_MACHINE_STATE *g_vcpu        = NULL;
EPT_STATE             *g_ept         = NULL;
UINT32                 g_cpu_count   = 0;
UINT64                 g_system_cr3  = 0;
UINT64                *g_msr_bitmap_invalid = NULL;
HOST_IDT_STATE         g_host_idt    = {0};

// Phase 5a: TSC at first vmexit (VMM is "alive" from this point on).
// Set lazily in VmmExit.c::vmexit_handler. STATUS_QUERY reads delta.
UINT64                 g_vmm_start_tsc = 0;

// Phase 7a: stealth lockdown latch. After cheat finishes setup (resolve_set
// + install + push_offsets), trigger via CPUID OPHX subleaf 0xFD. All magic
// CPUID leaves (OPHI/OPHR/OPHS/OPHX) thereafter passthrough to bare CPUID,
// hiding VMM identity from anti-cheat probes. VMCALL channel keeps working
// (dispatch via patched syscall, not CPUID).
UINT32 g_stealth_locked = 0;

// Phase 5b: kernel symbol VAs + EPROCESS offsets pushed from cheat exe via
// OP_SET_KERNEL_OFFSETS. Used by RESOLVE_TARGET (Phase 5c).
UINT64 g_ps_active_process_head_va = 0;
UINT16 g_off_active_process_links  = 0;
UINT16 g_off_unique_process_id     = 0;
UINT16 g_off_image_file_name       = 0;
UINT16 g_off_directory_table_base  = 0;
UINT16 g_off_section_base_address  = 0;
UINT16 g_off_peb                   = 0;
UINT32 g_kernel_offsets_set        = 0;

// Per-CPU NMI pending flag — referenced by AsmHostIdt.asm::asm_host_nmi_handler.
volatile LONG g_host_nmi_pending[MAX_PROCESSORS] = {0};
