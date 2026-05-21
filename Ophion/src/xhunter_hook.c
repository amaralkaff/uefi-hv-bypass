/*
*   xhunter_hook.c - EPT hook for xhunter1.sys command dispatch
*
*   Architecture:
*     1. Split the 2MB EPT page containing xhunter1's dispatch into 4KB pages
*     2. For the 4KB page containing the hook point:
*        - Read/Write  → original page (clean bytes for integrity checks)
*        - Execute     → shadow page  (patched with INT3 at hook offset)
*     3. On EPT violation (execute on read-only page or read on execute-only):
*        - Execute violation at hook address → enter intercept handler
*        - Read/write violation on shadow page → flip to original, arm MTF
*     4. MTF fires after one instruction → flip back to shadow
*
*   The intercept handler runs in VMX-root. It reads the IRP SystemBuffer
*   from the guest, extracts the xhunter1 command number, evaluates filter
*   rules, logs the event, and decides whether to pass or block.
*/
#include "hv.h"
#include "xhunter_hook.h"

/* shadow page: copy of original code page with INT3 patch at hook offset */
static DECLSPEC_ALIGN(PAGE_SIZE) UINT8 g_shadow_page[PAGE_SIZE];
static UINT64 g_shadow_page_pa = 0;
static UINT64 g_original_page_pa = 0;

/* saved original byte at hook point (replaced by 0xCC) */
static UINT8  g_original_byte = 0;

/* offset within 4KB page where the INT3 sits */
static UINT32 g_hook_page_offset = 0;

/* which PML1 entry we're manipulating */
static PEPT_PML1_ENTRY g_hooked_pml1 = NULL;

/* saved original PML1 entry for restore */
static EPT_PML1_ENTRY g_original_pml1 = {0};

/* execute-only PML1: guest reads see original, executes hit shadow */
static EPT_PML1_ENTRY g_exec_only_pml1 = {0};

/* read/write-only PML1: for MTF single-step (allows read of shadow, no exec) */
static EPT_PML1_ENTRY g_readwrite_pml1 = {0};

/* tracks whether we're in single-step mode after a read/write violation */
static volatile LONG g_mtf_restore_pending[MAX_PROCESSORS] = {0};

/* fetch the cached PML1 entry pointer for a specific VCPU's hook page */
static FORCEINLINE PEPT_PML1_ENTRY
xhook_pml1_for_core(UINT32 core_id)
{
    if (core_id >= 256 || !g_xhook)
        return NULL;
    PEPT_PML1_ENTRY arr = (PEPT_PML1_ENTRY)g_xhook->pml1_per_vcpu[core_id];
    if (!arr)
        return NULL;
    return &arr[g_xhook->pml1_index];
}

/*
 * Log a command intercept from VMX-root.
 * Lock-free: single producer per core (only one vmexit handler runs per core).
 */
static __forceinline VOID
xhook_log_event(UINT32 command, XH_FILTER_ACTION action, UINT64 cr3)
{
    LONG idx = InterlockedIncrement(&g_xhook->log_head) - 1;
    idx &= XH_LOG_MASK;

    g_xhook->log[idx].timestamp = __rdtsc();
    g_xhook->log[idx].guest_cr3 = cr3;
    g_xhook->log[idx].command   = command;
    g_xhook->log[idx].action    = action;

    InterlockedIncrement(&g_xhook->total_intercepted);
}

/*
 * Initialize xhook global state. Called from DriverEntry (PASSIVE_LEVEL).
 */
BOOLEAN
xhook_init(VOID)
{
    g_xhook = (XH_HOOK_STATE *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(XH_HOOK_STATE), HV_POOL_TAG);
    if (!g_xhook)
    {
        hv_log("[xhook] Failed to allocate hook state\n");
        return FALSE;
    }

    RtlZeroMemory(g_xhook, sizeof(XH_HOOK_STATE));

    /* default: log all commands, block none */
    for (UINT32 i = 0; i < XH_CMD_COUNT; i++)
        g_xhook->rules[i] = (LONG)XH_ACTION_LOG_ONLY;

    hv_log("[xhook] Hook state initialized (all commands LOG_ONLY)\n");
    return TRUE;
}

VOID
xhook_destroy(VOID)
{
    if (g_xhook)
    {
        if (g_xhook->active)
            xhook_teardown_ept();

        ExFreePoolWithTag(g_xhook, HV_POOL_TAG);
        g_xhook = NULL;
    }
}

/* forward declaration for KeGenericCallDpc — also declared in broadcast.c */
NTKERNELAPI VOID KeGenericCallDpc(PKDEFERRED_ROUTINE Routine, PVOID Context);
NTKERNELAPI VOID KeSignalCallDpcDone(PVOID SystemArgument1);
NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID SystemArgument2);

static VOID
xhook_dpc_invept(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    /* enter VMX-root via VMCALL gate; root handler executes INVEPT */
    asm_vmx_vmcall(VMCALL_INVEPT_ALL, 0, 0, 0);

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID
xhook_invept_all_broadcast(VOID)
{
    KeGenericCallDpc(xhook_dpc_invept, NULL);
}

/*
 * Set up the EPT hook on xhunter1's command dispatch function.
 * Called from modwatch callback or IOCTL at PASSIVE_LEVEL.
 *
 * Steps:
 *   1. Compute VA/PA of the hook target
 *   2. For each VCPU: split the 2MB page into 4KB
 *   3. Build shadow page (copy + INT3 patch)
 *   4. Set PML1: execute → shadow, read/write → original
 *   5. Invalidate EPT on all cores
 */
BOOLEAN
xhook_setup_ept(UINT64 xhunter_base, UINT64 dispatch_rva)
{
    if (!g_xhook || g_xhook->active)
        return FALSE;

    /* verify CPU supports execute-only EPT pages (required for stealth hook) */
    IA32_VMX_EPT_VPID_CAP_REGISTER vpid_cap;
    vpid_cap.AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP);
    if (!vpid_cap.ExecuteOnlyPages)
    {
        hv_log("[xhook] CPU does not support execute-only EPT pages — cannot hook\n");
        return FALSE;
    }

    UINT64 hook_va = xhunter_base + dispatch_rva;
    UINT64 hook_pa = va_to_pa((PVOID)hook_va);
    if (!hook_pa)
    {
        hv_log("[xhook] va_to_pa failed for hook VA 0x%llX\n", hook_va);
        return FALSE;
    }

    UINT64 page_pa = hook_pa & ~0xFFFULL;
    g_hook_page_offset = (UINT32)(hook_pa & 0xFFF);

    hv_log("[xhook] Target: base=0x%llX rva=0x%llX va=0x%llX pa=0x%llX page_offset=0x%X\n",
           xhunter_base, dispatch_rva, hook_va, hook_pa, g_hook_page_offset);

    /* build shadow page: copy original 4KB page, patch with INT3 */
    PVOID original_va = (PVOID)(hook_va & ~0xFFFULL);
    RtlCopyMemory(g_shadow_page, original_va, PAGE_SIZE);
    g_original_byte = g_shadow_page[g_hook_page_offset];
    g_shadow_page[g_hook_page_offset] = 0xCC;  /* INT3 */

    g_shadow_page_pa = va_to_pa(g_shadow_page);
    g_original_page_pa = page_pa;

    if (!g_shadow_page_pa)
    {
        hv_log("[xhook] va_to_pa failed for shadow page\n");
        return FALSE;
    }

    g_xhook->pml1_index = (UINT32)((hook_pa >> 12) & 0x1FF);

    /* split and hook on every VCPU */
    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        PVMM_EPT_PAGE_TABLE pt = g_vcpu[i].ept_page_table;
        if (!pt)
        {
            hv_log("[xhook] core %u has no EPT table — skipping\n", i);
            continue;
        }

        /* split the 2MB page and grab the PML1 array pointer (avoid pa_to_va) */
        PEPT_PML1_ENTRY pml1_array = NULL;
        if (!ept_split_large_page_ex(pt, page_pa, &pml1_array) || !pml1_array)
        {
            hv_log("[xhook] split_ex failed for core %u\n", i);
            return FALSE;
        }
        g_xhook->pml1_per_vcpu[i] = pml1_array;

        PEPT_PML1_ENTRY pml1 = &pml1_array[g_xhook->pml1_index];

        if (i == 0)
        {
            /* save originals from first core (all cores have same mapping) */
            g_hooked_pml1 = pml1;
            g_original_pml1.AsUInt = pml1->AsUInt;

            /* execute-only: points to shadow page (hooked code) */
            g_exec_only_pml1.AsUInt        = 0;
            g_exec_only_pml1.ReadAccess    = 0;
            g_exec_only_pml1.WriteAccess   = 0;
            g_exec_only_pml1.ExecuteAccess = 1;
            g_exec_only_pml1.MemoryType    = pml1->MemoryType;
            g_exec_only_pml1.PageFrameNumber = g_shadow_page_pa / PAGE_SIZE;

            /* clean RWX: points to original page (clean reads + single-step exec) */
            g_readwrite_pml1.AsUInt        = 0;
            g_readwrite_pml1.ReadAccess    = 1;
            g_readwrite_pml1.WriteAccess   = 1;
            g_readwrite_pml1.ExecuteAccess = 1;
            g_readwrite_pml1.MemoryType    = pml1->MemoryType;
            g_readwrite_pml1.PageFrameNumber = g_original_page_pa / PAGE_SIZE;
        }

        /* set to execute-only (shadow page) — reads see original via violation handler */
        pml1->AsUInt = g_exec_only_pml1.AsUInt;
    }

    /* invalidate EPT across all processors */
    xhook_invept_all_broadcast();

    g_xhook->xhunter_base = xhunter_base;
    g_xhook->hook_rva      = dispatch_rva;
    g_xhook->hook_va       = hook_va;
    g_xhook->hook_pa       = hook_pa;
    g_xhook->hook_page_pa  = page_pa;
    g_xhook->active         = TRUE;

    hv_log("[xhook] EPT hook active on all %u cores\n", g_cpu_count);
    return TRUE;
}

/*
 * Remove the EPT hook, restore original PML1 entries.
 */
VOID
xhook_teardown_ept(VOID)
{
    if (!g_xhook || !g_xhook->active)
        return;

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        PEPT_PML1_ENTRY pml1 = xhook_pml1_for_core(i);
        if (pml1)
            pml1->AsUInt = g_original_pml1.AsUInt;
    }

    xhook_invept_all_broadcast();
    g_xhook->active = FALSE;
    hv_log("[xhook] EPT hook removed\n");
}

/*
 * VMX-root: handle EPT violation that might be from our hook.
 * Returns TRUE if this violation was ours (caller should skip default handler).
 *
 * Two cases:
 *   (A) Execute violation on our page → INT3 hit → intercept command
 *   (B) Read/write violation on our page → integrity check → show clean page, arm MTF
 */
BOOLEAN
xhook_handle_ept_violation(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (!g_xhook || !g_xhook->active)
        return FALSE;

    UINT64 guest_phys = 0;
    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &guest_phys);

    UINT64 faulting_page = guest_phys & ~0xFFFULL;
    if (faulting_page != g_xhook->hook_page_pa)
        return FALSE;

    VMX_EXIT_QUALIFICATION_EPT_VIOLATION qual;
    qual.AsUInt = vcpu->exit_qual;

    if (qual.ExecuteAccess && !qual.EptExecutable)
    {
        /*
         * Case B: guest tried to execute on the read/write-only page.
         * This happens during MTF single-step: we showed the clean page for
         * a read, now the next instruction tries to execute from it.
         * Flip back to execute-only (shadow) immediately.
         */
        PEPT_PML1_ENTRY pml1 = xhook_pml1_for_core(vcpu->core_id);
        if (pml1)
            pml1->AsUInt = g_exec_only_pml1.AsUInt;

        ept_invept_single(vcpu->ept_pointer);
        vcpu->advance_rip = FALSE;
        return TRUE;
    }

    if ((qual.ReadAccess || qual.WriteAccess) && !qual.EptReadable)
    {
        /*
         * Case B: guest tried to read/write our execute-only page.
         * This is xhunter1 integrity-checking its own .text section.
         * Show the clean original page temporarily, arm MTF to flip back.
         */
        PEPT_PML1_ENTRY pml1 = xhook_pml1_for_core(vcpu->core_id);
        if (pml1)
            pml1->AsUInt = g_readwrite_pml1.AsUInt;

        ept_invept_single(vcpu->ept_pointer);

        /* arm monitor trap flag to restore after one guest instruction */
        size_t proc_ctrl = 0;
        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
        proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);

        g_mtf_restore_pending[vcpu->core_id] = 1;
        vcpu->advance_rip = FALSE;
        return TRUE;
    }

    /*
     * Case A: execute violation on execute-only page should not happen
     * (we allow execute). But if the guest hits our INT3 on the shadow page,
     * it causes a #BP exception VM-exit, not an EPT violation.
     * Handle that in the exception path instead.
     */

    return FALSE;
}

/*
 * VMX-root: handle Monitor Trap Flag exit.
 * After showing clean page for integrity check, flip back to execute-only.
 */
BOOLEAN
xhook_handle_mtf(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (!g_mtf_restore_pending[vcpu->core_id])
        return FALSE;

    g_mtf_restore_pending[vcpu->core_id] = 0;

    /* disable MTF */
    size_t proc_ctrl = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
    proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);

    /* restore execute-only (shadow page) */
    PEPT_PML1_ENTRY pml1 = xhook_pml1_for_core(vcpu->core_id);
    if (pml1)
        pml1->AsUInt = g_exec_only_pml1.AsUInt;

    ept_invept_single(vcpu->ept_pointer);
    vcpu->advance_rip = FALSE;
    return TRUE;
}

/*
 * VMX-root: called when a #BP exception exits from the guest.
 * Checks if RIP matches our INT3 hook. If so, intercepts the xhunter1
 * command dispatch, evaluates filter rules, and decides pass/block.
 *
 * Returns TRUE if this was our breakpoint.
 *
 * On entry, guest RIP points to the INT3 (0xCC). The real instruction
 * byte is g_original_byte. We need to:
 *   1. Read the xhunter1 command from the IRP SystemBuffer
 *   2. Evaluate filter rules
 *   3. PASS: restore original byte context, let execution continue
 *   4. BLOCK: modify guest state to skip the dispatch, return fake error
 */
BOOLEAN
xhook_handle_breakpoint(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (!g_xhook || !g_xhook->active)
        return FALSE;

    /*
     * VMCS_GUEST_RIP for software-exception VM-exit (INT3) holds the RIP
     * of the INT3 instruction itself; instruction length is available via
     * VM_EXIT_INSTRUCTION_LENGTH if needed for skip.
     */
    if (vcpu->vmexit_rip != g_xhook->hook_va)
        return FALSE;

    /*
     * We're at the xhunter1 dispatch entry point.
     * At this point in the call chain, RCX typically holds the IRP pointer
     * (standard Windows IRP dispatch convention: PDEVICE_OBJECT in RCX,
     * PIRP in RDX for IRP_MJ_WRITE handler, but after the validation
     * wrapper the SystemBuffer pointer may be in a register or on stack).
     *
     * For now: log the intercept with whatever context we can extract
     * from the guest registers. The command number extraction requires
     * reading guest memory, which we do carefully via MmIsAddressValid
     * checks (we're in VMX-root but can read guest memory since we share
     * the same physical address space with identity-mapped EPT).
     */
    PGUEST_REGS regs = vcpu->regs;

    /*
     * Try to extract command number from guest context.
     * The dispatch function receives the parsed command buffer.
     * RDX typically points to the PIRP in IRP_MJ_WRITE dispatch.
     * IRP->AssociatedIrp.SystemBuffer (+0x18) → XH_CMD → command at +12.
     *
     * This is architecture-dependent and may need adjustment based on
     * the actual calling convention at the hook point.
     */
    UINT32 command = 0;
    BOOLEAN got_command = FALSE;
    UINT64 guest_cr3 = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);

    /*
     * Two extraction paths verified against real xhunter1.sys + mock:
     *  - Real xhunter1 sub_*B568: RDX = PIRP, walk to SystemBuffer (+0x18)
     *    → magic at +4 → command at +12
     *  - Mock MockDispatchCommand: RCX = command int in 774..821
     *
     * RDX/PIRP path tried first because real driver is the production target.
     */
    UINT64 pirp = regs->rdx;
    if (pirp > 0xFFFF800000000000ULL && MmIsAddressValid((PVOID)pirp))
    {
        UINT64 sys_buf = *(UINT64 *)(pirp + IRP_SYSTEMBUF_OFFSET);
        if (sys_buf > 0xFFFF800000000000ULL && MmIsAddressValid((PVOID)sys_buf))
        {
            UINT32 magic = *(UINT32 *)(sys_buf + XH_OFF_MAGIC);
            if (magic == XH_REQUEST_MAGIC)
            {
                command = *(UINT32 *)(sys_buf + XH_OFF_COMMAND);
                got_command = TRUE;
            }
        }
    }
    if (!got_command)
    {
        UINT64 rcx_val = regs->rcx;
        if (rcx_val >= XH_CMD_MIN && rcx_val <= XH_CMD_MAX)
        {
            command = (UINT32)rcx_val;
            got_command = TRUE;
        }
    }

    /* evaluate filter rule */
    XH_FILTER_ACTION action = XH_ACTION_PASS;
    if (got_command && command >= XH_CMD_MIN && command <= XH_CMD_MAX)
    {
        action = (XH_FILTER_ACTION)InterlockedCompareExchange(
            &g_xhook->rules[command - XH_CMD_MIN],
            0, 0);  /* atomic read */
    }

    /* log the event */
    xhook_log_event(got_command ? command : 0xFFFFFFFF, action, guest_cr3);

    if (action == XH_ACTION_BLOCK)
    {
        /*
         * Block: make the dispatch function return immediately with
         * STATUS_INVALID_DEVICE_REQUEST (0xC0000010).
         * We set RAX to the error status and adjust RIP to the function's
         * return (simulate a RET by popping the return address from RSP).
         */
        UINT64 ret_addr = 0;
        UINT64 guest_rsp = 0;
        __vmx_vmread(VMCS_GUEST_RSP, &guest_rsp);

        if (MmIsAddressValid((PVOID)guest_rsp))
        {
            ret_addr = *(UINT64 *)guest_rsp;
            regs->rax = 0xC0000010ULL;  /* STATUS_INVALID_DEVICE_REQUEST */
            __vmx_vmwrite(VMCS_GUEST_RSP, guest_rsp + 8);
            __vmx_vmwrite(VMCS_GUEST_RIP, ret_addr);
        }
        else
        {
            /* can't read stack — fall through to pass */
            action = XH_ACTION_PASS;
        }
    }

    if (action != XH_ACTION_BLOCK)
    {
        /*
         * Pass/LogOnly: let the real dispatch run.
         * Swap PML1 to clean RWX (original page), rewind RIP to the
         * patched byte so the original instruction executes, arm MTF to
         * restore exec-only on next exit.
         */
        PEPT_PML1_ENTRY pml1 = xhook_pml1_for_core(vcpu->core_id);
        if (pml1)
            pml1->AsUInt = g_readwrite_pml1.AsUInt;

        ept_invept_single(vcpu->ept_pointer);

        /* arm MTF */
        size_t proc_ctrl = 0;
        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
        proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);

        g_mtf_restore_pending[vcpu->core_id] = 1;
    }

    vcpu->advance_rip = FALSE;
    return TRUE;
}

/*
 * IOCTL helpers — called from PASSIVE_LEVEL
 */

UINT32
xhook_log_read(PXH_LOG_ENTRY out_buf, UINT32 max_entries)
{
    if (!g_xhook)
        return 0;

    UINT32 count = 0;
    while (count < max_entries)
    {
        LONG tail = g_xhook->log_tail;
        LONG head = g_xhook->log_head;

        if (tail >= head)
            break;

        LONG idx = tail & XH_LOG_MASK;
        out_buf[count] = g_xhook->log[idx];

        if (InterlockedCompareExchange(&g_xhook->log_tail, tail + 1, tail) == tail)
            count++;
    }

    return count;
}

VOID
xhook_set_rule(UINT32 command, XH_FILTER_ACTION action)
{
    if (!g_xhook)
        return;

    if (command < XH_CMD_MIN || command > XH_CMD_MAX)
        return;

    InterlockedExchange(&g_xhook->rules[command - XH_CMD_MIN], (LONG)action);

    hv_log("[xhook] Rule: cmd %u → %s\n", command,
           action == XH_ACTION_PASS ? "PASS" :
           action == XH_ACTION_BLOCK ? "BLOCK" : "LOG_ONLY");
}

VOID
xhook_get_rules(LONG * out_rules, UINT32 count)
{
    if (!g_xhook || !out_rules)
        return;

    UINT32 copy = count < XH_CMD_COUNT ? count : XH_CMD_COUNT;
    for (UINT32 i = 0; i < copy; i++)
        out_rules[i] = InterlockedCompareExchange(&g_xhook->rules[i], 0, 0);
}

VOID
xhook_get_status(PXH_IOCTL_STATUS status_out)
{
    if (!g_xhook || !status_out)
        return;

    status_out->hook_active       = g_xhook->active;
    status_out->xhunter_base      = g_xhook->xhunter_base;
    status_out->hook_va           = g_xhook->hook_va;
    status_out->log_count         = (UINT32)((g_xhook->log_head - g_xhook->log_tail) & 0x7FFFFFFF);
    status_out->total_intercepted = (UINT32)g_xhook->total_intercepted;
}
