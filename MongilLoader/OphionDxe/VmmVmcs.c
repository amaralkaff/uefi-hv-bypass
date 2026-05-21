/*
 * VmmVmcs.c - VMX init + VMCS setup, ported from Ophion/src/vmx.c.
 *
 * Phase 2 deltas vs Ophion:
 *   - MmAllocateContiguousMemory + alignment trick replaced by
 *     EfiAllocateRuntimePages(1) — UEFI's AllocatePages already returns
 *     page-aligned PA, single-page region is sufficient.
 *   - va_to_pa identity (see VmmUtil.c).
 *   - All USE_PRIVATE_HOST_GDT / USE_PRIVATE_HOST_CR3 / USE_PRIVATE_HOST_IDT
 *     conditional code dropped — those branches use system GDT/CR3/IDT
 *     this phase. Phase 2.5 will reinstate the private versions when we
 *     prove VMLAUNCH works.
 *   - STEALTH_HIDE_CR4_VMXE branch dropped — stealth deferred to post-launch.
 *   - vmx_terminate not ported — no graceful unload from VMM in EFI Phase 2.
 *
 * vmx_init / vmx_virtualize_cpu / vmx_vmresume are wired but NOT yet called
 * from VmmArm. Phase 2 stop point: alloc paths compile and link.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <intrin.h>

#include "EfiCompat.h"
#include "ia32.h"
#include "hv_types.h"

extern VOID hv_log(IN CONST CHAR8 *fmt, ...);
extern VOID VmmLogVarSet(IN CONST CHAR16 *Name, IN CONST CHAR8 *Msg);
extern VOID VmmLogVarSetf(IN CONST CHAR16 *Name, IN CONST CHAR8 *Fmt, ...);
extern UINT64 hostgdt_get_gdt_base(VOID);
extern UINT64 hostgdt_get_tss_base(VOID);
extern UINT16 hostgdt_get_tr_sel(VOID);
extern UINT64 hostidt_get_base(VOID);
UINT64 va_to_pa(PVOID va);

extern UINT64 VmcsGetVmexitLoadListPa(VOID);
extern UINT32 VmcsGetVmexitLoadCount(VOID);
PVOID  pa_to_va(UINT64 pa);
UINT64 get_system_cr3(VOID);
UINT64 hostcr3_get(VOID);
VOID   segment_get_descriptor(PUCHAR gdt_base, UINT16 selector, VMX_SEGMENT_SELECTOR *result);
VOID   segment_fill_vmcs(PVOID gdt_base, UINT32 seg_reg, UINT16 selector);

extern UINT16 asm_get_es(VOID);
extern UINT16 asm_get_cs(VOID);
extern UINT16 asm_get_ss(VOID);
extern UINT16 asm_get_ds(VOID);
extern UINT16 asm_get_fs(VOID);
extern UINT16 asm_get_gs(VOID);
extern UINT16 asm_get_ldtr(VOID);
extern UINT16 asm_get_tr(VOID);
extern UINT64 asm_get_gdt_base(VOID);
extern UINT64 asm_get_idt_base(VOID);
extern UINT16 asm_get_gdt_limit(VOID);
extern UINT16 asm_get_idt_limit(VOID);
extern UINT64 asm_get_rflags(VOID);
extern VOID   asm_enable_vmx(VOID);
extern VOID   asm_vmx_save_state(VOID);
extern VOID   asm_vmx_restore_state(VOID);
extern VOID   asm_vmexit_handler(VOID);

extern BOOLEAN ept_init(VOID);
extern VIRTUAL_MACHINE_STATE *g_vcpu;
extern UINT32                 g_cpu_count;
extern UINT64                 g_system_cr3;

UINT32
vmx_adjust_controls(UINT32 requested, UINT32 capability_msr)
{
    MSR msr_val = {0};
    msr_val.Flags = __readmsr(capability_msr);
    // bit == 0 in high word -> must be zero, bit == 1 in low word -> must be one
    requested &= msr_val.Fields.High;
    requested |= msr_val.Fields.Low;
    return requested;
}

VOID
vmx_set_fixed_bits(VOID)
{
    CR_FIXED fixed = {0};
    CR0      cr0   = {0};
    CR4      cr4   = {0};

    fixed.Flags  = __readmsr(IA32_VMX_CR0_FIXED0);
    cr0.AsUInt   = __readcr0();
    cr0.AsUInt  |= fixed.Fields.Low;
    fixed.Flags  = __readmsr(IA32_VMX_CR0_FIXED1);
    cr0.AsUInt  &= fixed.Fields.Low;
    __writecr0(cr0.AsUInt);

    fixed.Flags  = __readmsr(IA32_VMX_CR4_FIXED0);
    cr4.AsUInt   = __readcr4();
    cr4.AsUInt  |= fixed.Fields.Low;
    fixed.Flags  = __readmsr(IA32_VMX_CR4_FIXED1);
    cr4.AsUInt  &= fixed.Fields.Low;
    __writecr4(cr4.AsUInt);
}

BOOLEAN
vmx_alloc_vmxon(VIRTUAL_MACHINE_STATE *vcpu)
{
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    PVOID                   region;

    region = EfiAllocateRuntimePages(1);  // 4KB page-aligned
    if (!region)
        return FALSE;

    vmx_basic.AsUInt    = __readmsr(IA32_VMX_BASIC);
    *(UINT64 *)region   = vmx_basic.VmcsRevisionId;

    vcpu->vmxon_va = (UINT64)(UINTN)region;
    vcpu->vmxon_pa = va_to_pa(region);
    return TRUE;
}

BOOLEAN
vmx_alloc_vmcs(VIRTUAL_MACHINE_STATE *vcpu)
{
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    PVOID                   region;

    region = EfiAllocateRuntimePages(1);
    if (!region)
        return FALSE;

    vmx_basic.AsUInt   = __readmsr(IA32_VMX_BASIC);
    *(UINT64 *)region  = vmx_basic.VmcsRevisionId;

    vcpu->vmcs_va = (UINT64)(UINTN)region;
    vcpu->vmcs_pa = va_to_pa(region);
    return TRUE;
}

BOOLEAN
vmx_clear_vmcs(VIRTUAL_MACHINE_STATE *vcpu)
{
    if (__vmx_vmclear(&vcpu->vmcs_pa)) {
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}

//
// vmx_smoke_test - Phase 2.5b: VMXON + VMCLEAR + VMPTRLD + VMREAD readback + VMXOFF.
// Proves CR0/CR4 fixed-bit fixup, IA32_FEATURE_CONTROL, VMXON region, VMCS region,
// VMCS revision id stamp all work. No VMLAUNCH (deferred to 2.5c).
//
// Called from EBS callback — VMX intrinsics are CPU ops, not boot services.
//
BOOLEAN
vmx_smoke_test(VOID)
{
    if (!g_vcpu || g_cpu_count == 0) {
        hv_log("[hv] smoke: g_vcpu null or no vcpus\n");
        return FALSE;
    }

    asm_enable_vmx();
    vmx_set_fixed_bits();

    UINT64 cr4 = __readcr4();
    hv_log("[hv] smoke: CR4=0x%llx VMXE=%u\n",
           cr4, (UINT32)((cr4 >> 13) & 1));

    // Phase 7d-spoof-coexist: detect if another agent (e.g. NOVA spoofer's
    // mp.efi) is already in VMX root. CR4.VMXE=1 only proves VMX is enabled,
    // not that VMXON has been issued. Try VMXON; if already-on (error code 3
    // or invalid VMCS state) we abort cleanly without crashing.
    //
    // SDM 30.3 VMXON: if VMX already on, instr fails with success-flag=0,
    // VM_INSTRUCTION_ERROR=3 ("VMXON in VMX root"). __vmx_on returns
    // non-zero on failure. We treat any failure as "skip VMM" rather than
    // crash — spoofer chain still completes via boot.efi.
    UINT64 vmxon_pa = g_vcpu[0].vmxon_pa;
    int vmxon_ret = __vmx_on(&vmxon_pa);
    if (vmxon_ret) {
        hv_log("[hv] smoke: VMXON failed (ret=%d vmxon_pa=0x%llx) - "
               "another VMX root present? skipping VMM init\n",
               vmxon_ret, vmxon_pa);
        VmmLogVarSet(L"OphnLastErr", "VMXON_already_on_skipping");
        return FALSE;
    }
    hv_log("[hv] smoke: VMXON ok\n");

    UINT64 vmcs_pa = g_vcpu[0].vmcs_pa;
    if (__vmx_vmclear(&vmcs_pa)) {
        hv_log("[hv] smoke: VMCLEAR failed\n");
        __vmx_off();
        return FALSE;
    }
    hv_log("[hv] smoke: VMCLEAR ok\n");

    if (__vmx_vmptrld(&vmcs_pa)) {
        hv_log("[hv] smoke: VMPTRLD failed\n");
        __vmx_off();
        return FALSE;
    }
    hv_log("[hv] smoke: VMPTRLD ok\n");

    // Smoke vmwrite + vmread on a benign field (VMCS_GUEST_VMCS_LINK_POINTER).
    // SDM 24.4.2: link pointer is natural-width, ~0ULL = no shadow VMCS.
    if (__vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL)) {
        hv_log("[hv] smoke: VMWRITE failed\n");
        __vmx_off();
        return FALSE;
    }
    UINT64 readback = 0;
    if (__vmx_vmread(VMCS_GUEST_VMCS_LINK_POINTER, &readback)) {
        hv_log("[hv] smoke: VMREAD failed\n");
        __vmx_off();
        return FALSE;
    }
    hv_log("[hv] smoke: VMWRITE/VMREAD ok (link_ptr=0x%llx)\n", readback);

    __vmx_off();
    hv_log("[hv] smoke: VMXOFF ok\n");
    return TRUE;
}

BOOLEAN
vmx_load_vmcs(VIRTUAL_MACHINE_STATE *vcpu)
{
    if (__vmx_vmptrld(&vcpu->vmcs_pa))
        return FALSE;
    return TRUE;
}

BOOLEAN
vmx_setup_vmcs(VIRTUAL_MACHINE_STATE *vcpu, PVOID guest_stack)
{
    UINT32                  pri_proc;
    UINT32                  sec_proc;
    UINT64                  gdt_base;
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    VMX_SEGMENT_SELECTOR    seg_sel   = {0};

    vmx_basic.AsUInt = __readmsr(IA32_VMX_BASIC);

    // Mask RPL/TI bits (bits 0-2) per Intel SDM 24.5.
    __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, asm_get_es() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, asm_get_cs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, asm_get_ss() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, asm_get_ds() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, asm_get_fs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, asm_get_gs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, asm_get_tr() & 0xF8);

    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);
    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL,          __readmsr(IA32_DEBUGCTL));

    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);

    // Phase 7c-4b: wire VMEXIT_MSR_LOAD with single entry IA32_DEBUGCTL=0.
    // Hardware clears host DEBUGCTL atomically on every VMEXIT -> host runs
    // with LBR/BTM/BTS off. Allocated in VmmInit::VmcsAllocMinimalLoadList.
    // If list pa is 0 (alloc failed earlier), fall back to count=0 (Phase
    // 7c-4a behavior).
    {
        UINT64 load_pa = VmcsGetVmexitLoadListPa();
        UINT32 load_ct = VmcsGetVmexitLoadCount();
        if (load_pa != 0 && load_ct > 0) {
            __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_ADDRESS, load_pa);
            __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT,   load_ct);
        } else {
            __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
        }
    }
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

    gdt_base = asm_get_gdt_base();

    vcpu->original_gdt_base    = gdt_base;
    vcpu->original_gdt_limit   = asm_get_gdt_limit();
    vcpu->original_tr_selector = asm_get_tr();

    segment_fill_vmcs((PVOID)gdt_base, ES,   asm_get_es());
    segment_fill_vmcs((PVOID)gdt_base, CS,   asm_get_cs());
    segment_fill_vmcs((PVOID)gdt_base, SS,   asm_get_ss());
    segment_fill_vmcs((PVOID)gdt_base, DS,   asm_get_ds());
    segment_fill_vmcs((PVOID)gdt_base, FS,   asm_get_fs());
    segment_fill_vmcs((PVOID)gdt_base, GS,   asm_get_gs());
    segment_fill_vmcs((PVOID)gdt_base, LDTR, asm_get_ldtr());
    segment_fill_vmcs((PVOID)gdt_base, TR,   asm_get_tr());

    // Phase 2.7: UEFI bare-metal has TR=0 → segment_fill_vmcs marks GUEST TR
    // Unusable. SDM 26.3.1.2 rejects unusable guest TR in IA-32e mode →
    // VMENTRY fails reason=0x21 (VMENTRY_FAILURE_GUEST_STATE). Override with
    // our private TSS, busy-64-bit-TSS access rights (type=11, S=0, P=1).
    {
        UINT16 tr_sel  = hostgdt_get_tr_sel();
        UINT64 tss_base = hostgdt_get_tss_base();
        if (tr_sel != 0 && tss_base != 0) {
            __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR,      tr_sel & 0xF8);
            __vmx_vmwrite(VMCS_GUEST_TR_BASE,          tss_base);
            __vmx_vmwrite(VMCS_GUEST_TR_LIMIT,         0x67);
            __vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, 0x8B); // P=1,DPL=0,S=0,Type=11 (busy 64-bit TSS)
        }
    }

    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

    pri_proc = vmx_adjust_controls(
        CPU_BASED_VM_EXEC_CTRL_USE_TSC_OFFSETTING |
        CPU_BASED_VM_EXEC_CTRL_USE_MSR_BITMAPS |
        CPU_BASED_VM_EXEC_CTRL_USE_IO_BITMAPS |
        CPU_BASED_VM_EXEC_CTRL_ACTIVATE_SECONDARY_CONTROLS,
        vmx_basic.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS);

    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pri_proc);

    vcpu->mov_dr_exiting = !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_MOV_DR_EXITING);
    vcpu->guest_cr8      = (UINT8)__readcr8();

    // PHASE 2.7: re-enable EPT + VPID. Wedge was HOST_IDTR pointing at
    // firmware IDT (reclaimed by Windows post-EBS) → first NMI/exception
    // in vmexit handler triple-faults. Now using private IDT in runtime
    // pages so EPT can come back on.
    //
    // PHASE 3d-i: add UNRESTRICTED_GUEST. Required for SIPI handler to put
    // guest into real-mode at AP startup. No effect on BSP path (long mode).
    sec_proc = vmx_adjust_controls(
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_EPT |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_VPID |
        CPU_BASED_VM_EXEC_CTRL2_UNRESTRICTED_GUEST |
        CPU_BASED_VM_EXEC_CTRL2_RDTSCP |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_INVPCID |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_XSAVES,
        IA32_VMX_PROCBASED_CTLS2);

    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, sec_proc);

    // PHASE 2.5: minimum-trap config — only CPUID + VMCALL fire (always
    // unconditional in Intel VT-x). NMI exiting / virtual NMI both intercept
    // unhandled events that wedge guest. Re-enable in Phase 2.6 once handlers
    // exist.
    UINT32 pin_ctrl = vmx_adjust_controls(0,
        vmx_basic.VmxControls ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS);

    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, pin_ctrl);

    // PHASE 2.5: no #BP intercept (Phase 4 EPT hook re-enables).
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, 0);

    UINT32 exit_ctrl = vmx_adjust_controls(
        VM_EXIT_CTRL_HOST_ADDRESS_SPACE_SIZE |
        VM_EXIT_CTRL_SAVE_DEBUG_CONTROLS |
        VM_EXIT_CTRL_ACK_INTERRUPT_ON_EXIT,
        vmx_basic.VmxControls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS);

    __vmx_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS, exit_ctrl);

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS,
                  vmx_adjust_controls(
                      VM_ENTRY_CTRL_IA32E_MODE_GUEST |
                      VM_ENTRY_CTRL_LOAD_DEBUG_CONTROLS,
                      vmx_basic.VmxControls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS));

    // CR0 fixed-bit shadow + WP (see feedback_vmx_cr0_shadow.md).
    // PHASE 2.5: temporarily mask=0 so guest CR0 writes pass through without
    // VMEXIT. Windows kernel toggles CR0.WP during boot; without a MOV-CR
    // emulation handler, intercepting WP wedges boot. Re-enable mask once
    // VmmExit.c::handle_mov_cr is implemented (Phase 2.6).
    {
        __vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, __readcr0());
    }

    // CR4: Phase 2 = pass-through (no VMXE hiding).
    __vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, 0);

    __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());
    __vmx_vmwrite(VMCS_GUEST_DR7, 0x400);

    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);

    __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

    // Phase 2.5: HOST_CR3 = private host CR3 (deep-clone of system PML4 built
    // by hostcr3_build at VmmInitialize time). If hostcr3 wasn't built yet,
    // fall back to current CR3.
    {
        UINT64 host_cr3 = hostcr3_get();
        if (host_cr3 == 0)
            host_cr3 = get_system_cr3();
        __vmx_vmwrite(VMCS_HOST_CR3, host_cr3);
    }

    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE,  asm_get_gdt_base());
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, asm_get_gdt_limit());
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE,  asm_get_idt_base());
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, asm_get_idt_limit());
    __vmx_vmwrite(VMCS_GUEST_RFLAGS,     asm_get_rflags());

    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    segment_get_descriptor((PUCHAR)asm_get_gdt_base(), asm_get_tr(), &seg_sel);
    // Phase 2.5d: override host TR with our private TSS in private host GDT.
    // UEFI bare-metal has TR=0 which violates SDM 26.2.3 host-state checks.
    {
        UINT16 host_tr  = hostgdt_get_tr_sel();
        UINT64 host_gdt = hostgdt_get_gdt_base();
        UINT64 host_tss = hostgdt_get_tss_base();
        if (host_tr != 0 && host_gdt != 0) {
            __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, host_tr & 0xF8);
            __vmx_vmwrite(VMCS_HOST_TR_BASE,     host_tss);
            __vmx_vmwrite(VMCS_HOST_GDTR_BASE,   host_gdt);
        } else {
            __vmx_vmwrite(VMCS_HOST_TR_BASE,   seg_sel.Base);
            __vmx_vmwrite(VMCS_HOST_GDTR_BASE, asm_get_gdt_base());
        }
    }
    // Phase 2.7: HOST_IDTR_BASE = our private IDT (firmware IDT pages get
    // reclaimed by Windows post-EBS — was the wedge cause).
    {
        UINT64 host_idt = hostidt_get_base();
        if (host_idt != 0) {
            __vmx_vmwrite(VMCS_HOST_IDTR_BASE, host_idt);
        } else {
            __vmx_vmwrite(VMCS_HOST_IDTR_BASE, asm_get_idt_base());
        }
    }

    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));

    __vmx_vmwrite(VMCS_HOST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, vcpu->msr_bitmap_pa);
    __vmx_vmwrite(VMCS_CTRL_IO_BITMAP_A_ADDRESS, vcpu->io_bitmap_pa_a);
    __vmx_vmwrite(VMCS_CTRL_IO_BITMAP_B_ADDRESS, vcpu->io_bitmap_pa_b);

    __vmx_vmwrite(VMCS_CTRL_EPT_POINTER, vcpu->ept_pointer.AsUInt);
    __vmx_vmwrite(VIRTUAL_PROCESSOR_ID, VPID_TAG);

    __vmx_vmwrite(VMCS_GUEST_RSP, (UINT64)guest_stack);
    __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)asm_vmx_restore_state);

    // Stack layout: top-8 = vcpu pointer, top-16 = HOST_RSP (16-byte aligned).
    *(VIRTUAL_MACHINE_STATE **)(vcpu->vmm_stack + VMM_STACK_SIZE - VMM_STACK_VCPU_OFFSET) = vcpu;

    __vmx_vmwrite(VMCS_HOST_RSP, vcpu->vmm_stack + VMM_STACK_SIZE - 16);
    __vmx_vmwrite(VMCS_HOST_RIP, (UINT64)asm_vmexit_handler);

    return TRUE;
}

// Per-core VMXON+VMLAUNCH driver. Called from asm_vmx_save_state via DPC in
// Ophion; in EFI Phase 2.5 will be called directly on BSP from VmmArm.
// guest_stack is the saved RSP from asm_vmx_save_state.
//
// Phase 3d-iii: also called from AP procedure (StartupThisAP / StartupAllAPs).
// AP must wrmsr IA32_TSC_AUX = myid BEFORE calling asm_vmx_save_state — this
// function reads TSC_AUX to index g_vcpu[]. NV log writes guarded with
// `if (core == 0)` since SetVariable from AP context is undefined.
BOOLEAN EFIAPI
vmx_virtualize_cpu(IN VOID *guest_stack)
{
    // Read current core via TSC_AUX (same as Ophion vmx_get_cpu_id).
    UINT32                  core      = (UINT32)(__readmsr(IA32_TSC_AUX) & 0xFFF);
    VIRTUAL_MACHINE_STATE  *vcpu      = &g_vcpu[core];
    UINT64                  err_code  = 0;
    BOOLEAN                 is_bsp    = (core == 0);

    vcpu->core_id    = core;
    vcpu->launch_err = 0;

    asm_enable_vmx();
    vmx_set_fixed_bits();

    if (__vmx_on(&vcpu->vmxon_pa)) {
        hv_log("[hv] VMXON failed on core %u\n", core);
        if (is_bsp) VmmLogVarSet(L"OphnLastErr", "VMXON_failed");
        vcpu->launch_err = 0xFF01;
        return FALSE;
    }

    if (!vmx_clear_vmcs(vcpu)) {
        if (is_bsp) VmmLogVarSet(L"OphnLastErr", "VMCLEAR_failed");
        vcpu->launch_err = 0xFF02;
        return FALSE;
    }

    if (!vmx_load_vmcs(vcpu)) {
        if (is_bsp) VmmLogVarSet(L"OphnLastErr", "VMPTRLD_failed");
        vcpu->launch_err = 0xFF03;
        return FALSE;
    }

    vmx_setup_vmcs(vcpu, guest_stack);

    // Dump host-state fields BEFORE vmlaunch on BSP only — SetVariable from AP
    // context is undefined behavior on some firmware. AP launch result captured
    // via vcpu->launched + vcpu->launch_err in BSP-side aggregate after dispatch.
    if (is_bsp) {
        UINT64 h_cr0=0, h_cr3=0, h_cr4=0, h_rsp=0, h_rip=0;
        UINT64 h_cs=0, h_ss=0, h_tr=0, h_ds=0, h_es=0, h_fs=0, h_gs=0;
        UINT64 h_tr_base=0, h_gdtr_base=0, h_idtr_base=0;
        UINT64 h_fs_base=0, h_gs_base=0;
        __vmx_vmread(VMCS_HOST_CR0, &h_cr0);
        __vmx_vmread(VMCS_HOST_CR3, &h_cr3);
        __vmx_vmread(VMCS_HOST_CR4, &h_cr4);
        __vmx_vmread(VMCS_HOST_RSP, &h_rsp);
        __vmx_vmread(VMCS_HOST_RIP, &h_rip);
        __vmx_vmread(VMCS_HOST_CS_SELECTOR, &h_cs);
        __vmx_vmread(VMCS_HOST_SS_SELECTOR, &h_ss);
        __vmx_vmread(VMCS_HOST_TR_SELECTOR, &h_tr);
        __vmx_vmread(VMCS_HOST_DS_SELECTOR, &h_ds);
        __vmx_vmread(VMCS_HOST_ES_SELECTOR, &h_es);
        __vmx_vmread(VMCS_HOST_FS_SELECTOR, &h_fs);
        __vmx_vmread(VMCS_HOST_GS_SELECTOR, &h_gs);
        __vmx_vmread(VMCS_HOST_TR_BASE, &h_tr_base);
        __vmx_vmread(VMCS_HOST_GDTR_BASE, &h_gdtr_base);
        __vmx_vmread(VMCS_HOST_IDTR_BASE, &h_idtr_base);
        __vmx_vmread(VMCS_HOST_FS_BASE, &h_fs_base);
        __vmx_vmread(VMCS_HOST_GS_BASE, &h_gs_base);
        VmmLogVarSetf(L"OphnHostState",
            "cs=%x ss=%x ds=%x es=%x fs=%x gs=%x tr=%x cr0=%llx cr3=%llx cr4=%llx rsp=%llx rip=%llx tr_base=%llx gdt=%llx idt=%llx fsbase=%llx gsbase=%llx",
            (UINT32)h_cs, (UINT32)h_ss, (UINT32)h_ds, (UINT32)h_es,
            (UINT32)h_fs, (UINT32)h_gs, (UINT32)h_tr,
            h_cr0, h_cr3, h_cr4, h_rsp, h_rip,
            h_tr_base, h_gdtr_base, h_idtr_base, h_fs_base, h_gs_base);
    }

    vcpu->launched = TRUE;
    if (is_bsp) VmmLogVarSet(L"OphnLastErr", "pre_vmlaunch");

    __vmx_vmlaunch();

    // Reach here only on VMLAUNCH failure.
    vcpu->launched = FALSE;
    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &err_code);
    vcpu->launch_err = err_code;
    __vmx_off();
    hv_log("[hv] VMLAUNCH failed on core %u, error 0x%llx\n", core, err_code);
    if (is_bsp) {
        VmmLogVarSetf(L"OphnLastErr", "VMLAUNCH_failed err=0x%llx core=%u", err_code, core);
    }
    return FALSE;
}

VOID EFIAPI
vmx_vmresume(VOID)
{
    __vmx_vmresume();

    UINT64 err_code = 0;
    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &err_code);
    __vmx_off();
    hv_log("[hv] VMRESUME failed, error 0x%llx\n", err_code);
}

UINT64 EFIAPI
vmx_return_rsp_for_vmxoff(VOID)
{
    // Real impl: return guest RSP captured in vmexit handler. Phase 2 stub.
    return 0;
}

UINT64 EFIAPI
vmx_return_rip_for_vmxoff(VOID)
{
    return 0;
}

UINT32
VmmBspLaunched(VOID)
{
    if (!g_vcpu) return 0;
    return g_vcpu[0].launched ? 1 : 0;
}

BOOLEAN
vmx_check_support(VOID)
{
    CPUID                          data      = {0};
    IA32_FEATURE_CONTROL_REGISTER  feat_ctrl = {0};

    __cpuid((int *)&data, 1);
    if (!_bittest((const long *)&data.ecx, CPUID_VMX_BIT))
        return FALSE;

    feat_ctrl.AsUInt = __readmsr(IA32_FEATURE_CONTROL);
    if (feat_ctrl.EnableVmxOutsideSmx == FALSE)
        return FALSE;

    return TRUE;
}

//
// vmx_init - top-level Ophion VMM init.
//
// Phase 2 deltas:
//   - g_cpu_count comes from gMpServices->GetNumberOfProcessors at boot, not
//     KeQueryActiveProcessorCount. Phase 2 BSP-only: hard-code 1 for now.
//     Phase 3 will wire MP services + AP SIPI intercept.
//   - Pool allocations for per-VCPU bitmaps/stacks routed through
//     EfiAllocateRuntimePages.
//   - broadcast_virtualize_all (DPC fanout) NOT called — Phase 2.5 will
//     add direct vmx_virtualize_cpu(rsp) call from VmmArm on BSP.
//
BOOLEAN
vmx_init(UINT32 cpu_count)
{
    g_cpu_count = cpu_count;

    UINTN vcpu_pages = (sizeof(VIRTUAL_MACHINE_STATE) * g_cpu_count + PAGE_SIZE - 1) / PAGE_SIZE;
    g_vcpu = (VIRTUAL_MACHINE_STATE *)EfiAllocateRuntimePages(vcpu_pages);
    if (!g_vcpu)
        return FALSE;

    if (!vmx_check_support()) {
        hv_log("[hv] VMX not supported\n");
        return FALSE;
    }

    if (!ept_init()) {
        hv_log("[hv] EPT init failed\n");
        return FALSE;
    }

    UINTN stack_pages = (VMM_STACK_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;

    for (UINT32 i = 0; i < g_cpu_count; i++) {
        VIRTUAL_MACHINE_STATE *vcpu = &g_vcpu[i];

        vcpu->vmm_stack = (UINT64)(UINTN)EfiAllocateRuntimePages(stack_pages);
        if (!vcpu->vmm_stack) return FALSE;

        // MSR bitmap (1 page, all zeros = no MSR VM-exits).
        PVOID msr_bm = EfiAllocateRuntimePages(1);
        if (!msr_bm) return FALSE;
        vcpu->msr_bitmap_va = (UINT64)(UINTN)msr_bm;

        // PHASE 2.5: bitmap kept all-zero = no MSR VM-exits. Phase 2.6 will
        // re-enable TSC + FC + VMX cap intercepts once handlers exist.
        // Original Ophion MSR intercepts disabled here for boot stability:
        //   ((PUCHAR)vcpu->msr_bitmap_va)[0x10 / 8] |= (UCHAR)(1 << (0x10 % 8));
        //   ((PUCHAR)vcpu->msr_bitmap_va)[0x3A / 8] |= (UCHAR)(1 << (0x3A % 8));
        //   ((PUCHAR)vcpu->msr_bitmap_va)[0x800 + 0x3A / 8] |= (UCHAR)(1 << (0x3A % 8));
        //   for (UINT32 m = 0x480; m <= 0x493; m++) {
        //       ((PUCHAR)vcpu->msr_bitmap_va)[m / 8]         |= (UCHAR)(1 << (m % 8));
        //       ((PUCHAR)vcpu->msr_bitmap_va)[0x800 + m / 8] |= (UCHAR)(1 << (m % 8));
        //   }

        vcpu->msr_bitmap_pa = va_to_pa((PVOID)(UINTN)vcpu->msr_bitmap_va);

        // I/O Bitmap A (ports 0x0000-0x7FFF).
        PVOID io_a = EfiAllocateRuntimePages(1);
        if (!io_a) return FALSE;
        vcpu->io_bitmap_va_a = (UINT64)(UINTN)io_a;
        vcpu->io_bitmap_pa_a = va_to_pa(io_a);

        // I/O Bitmap B (ports 0x8000-0xFFFF).
        PVOID io_b = EfiAllocateRuntimePages(1);
        if (!io_b) return FALSE;
        vcpu->io_bitmap_va_b = (UINT64)(UINTN)io_b;
        vcpu->io_bitmap_pa_b = va_to_pa(io_b);

        if (!vmx_alloc_vmxon(vcpu)) return FALSE;
        if (!vmx_alloc_vmcs(vcpu))  return FALSE;
    }

    hv_log("[hv] vmx_init: %u vcpu(s) prepared, VMXON deferred to Phase 2.5\n", g_cpu_count);
    return TRUE;
}
