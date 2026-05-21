/*
 * VmmExit.c - minimal Phase 2 vm-exit dispatcher.
 *
 * Replaces the VmmStubs.c::vmexit_handler stub. Implements just enough to:
 *   - CPUID (exit reason 10): pass through to bare CPUID, write back to GPRs,
 *     advance guest RIP by VM-exit instruction length, vmresume.
 *   - VMCALL (18): if rcx == VMCALL_VMXOFF and signature regs match, signal
 *     VMXOFF path to AsmVmexitHandler.asm. Otherwise inject #UD.
 *   - everything else: advance RIP + vmresume. Best-effort fall-through so a
 *     stray exit doesn't crash; real handlers come post-Phase-2.5.
 *
 * GUEST_REGS struct layout matches AsmVmexitHandler.asm push order — the asm
 * stack-frame doc in that file is the source of truth.
 *
 * Returns: TRUE = vmxoff path (asm restores guest RIP/RSP and rets),
 *          FALSE = vmresume.
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <intrin.h>

#include "EfiCompat.h"
#include "ia32.h"
#include "hv_types.h"
#include "../include/OphionAbi.h"

extern VOID hv_log(IN CONST CHAR8 *fmt, ...);
extern VOID vmexit_inject_ud(VOID);
extern VOID VmmLogVarSetf(IN CONST CHAR16 *Name, IN CONST CHAR8 *Fmt, ...);
extern VOID VmmLogVarSet(IN CONST CHAR16 *Name, IN CONST CHAR8 *Msg);
extern VOID ophion_resolve_all_once(UINT64 guest_cr3);
extern VOID ophion_resolve_get(UINT32 subleaf,
                               UINT32 *out_eax, UINT32 *out_ebx,
                               UINT32 *out_ecx, UINT32 *out_edx);
extern UINT32 ophion_resolve_set_ncp(UINT64 cr3, UINT32 rva);

#include "VmmPerCpuLog.h"
extern UINT32 ophion_install_do(UINT64 cr3);
extern VOID   ophion_install_get(UINT32 subleaf,
                                 UINT32 *out_eax, UINT32 *out_ebx,
                                 UINT32 *out_ecx, UINT32 *out_edx);
extern UINT32 ophion_install_do_cloaked(UINT64 cr3);
extern VOID   ophion_install_cloak_get(UINT32 subleaf,
                                       UINT32 *out_eax, UINT32 *out_ebx,
                                       UINT32 *out_ecx, UINT32 *out_edx);
extern UINTN  vmm_guest_read(UINT64 cr3, UINT64 va, VOID *dst, UINTN size);
extern UINTN  vmm_guest_write(UINT64 cr3, UINT64 va, CONST VOID *src, UINTN size);
extern UINT32 VmcallDispatch(IN UINT64 session_key_in_rax,
                             IN UINT32 op_code_in_rdx,
                             IN VOID *caller_buf,
                             IN UINT32 caller_buf_size,
                             IN UINT64 caller_rip,
                             IN UINT64 caller_cr3);

// Phase 5e: trampoline RIP-range gate. caller_rip at vmexit must be inside
// [g_trampoline_va, g_trampoline_va + g_trampoline_size) — i.e. our trampoline
// is the ONLY caller that can reach VmcallDispatch with the magic handle.
extern UINT64 g_trampoline_va;
extern UINTN  g_trampoline_size;
extern UINT32 g_trampoline_built;

// Phase 7d step 3+4: EPT cloak helpers (impl in VmmEpt.c).
extern BOOLEAN ept_cloak_violation_swap_to_read(UINT64 gphys, UINT64 *out_alt_pfn,
                                                VOID **out_pml1);
extern VOID    ept_cloak_mtf_swap_to_exec(VOID *pml1, UINT64 alt_pfn);
extern VOID    ept_invept_single(EPT_POINTER ept_ptr);
extern EPT_POINTER ept_get_eptp_bsp(VOID);

// Phase 7d step 4: MTF (Monitor Trap Flag) ctrl bit toggle. Single-step the
// guest exactly one instruction so the read-view of a cloaked page is only
// exposed for one fetch (PG SHA hash reads then promptly traps back to us).
static VOID
ept_set_mtf(VOID)
{
    UINT64 ctrls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &ctrls);
    ctrls |= CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ctrls);
}

static VOID
ept_clear_mtf(VOID)
{
    UINT64 ctrls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &ctrls);
    ctrls &= ~(UINT64)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ctrls);
}

// Diagnostic counters (visible via OPHR future subleaf).
UINT32 g_ept_violation_cloaks = 0;
UINT32 g_ept_violation_other  = 0;
UINT32 g_mtf_restores         = 0;

// Diagnostic for OPHR sub 16: count rejected non-trampoline VMCALLs.
UINT32 g_vmcall_rip_rejects = 0;
UINT64 g_vmcall_last_bad_rip = 0;

#define OPHION_VMCALL_MAGIC_HANDLE_U64  0xCAFEDEADBEEF1234ULL
#define OPHION_VMCALL_SCRATCH_BYTES     0x1000

// Static counter so we only log first N vmexits (avoid flash wear / overflow).
static UINT32 g_exit_count = 0;

// Phase 7d-debug: per-reason histogram of vmexits. Volatile (lost on freeze)
// but readable via OPHR sub 32 if VMM survives. Total exits ever = sum.
static UINT32 g_exit_hist[64] = {0};
// First-ever-seen unhandled reason. NV-stamped once on default branch entry
// so post-freeze reboot reveals the wedging reason via NV var OphnFirstBad.
static UINT32 g_first_bad_reason = 0xFFFF;

VOID
vmexit_advance_rip(VOID)
{
    UINT64 rip = 0;
    UINT64 len = 0;
    __vmx_vmread(VMCS_GUEST_RIP, &rip);
    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &len);
    __vmx_vmwrite(VMCS_GUEST_RIP, rip + len);
}

static VOID
handle_cpuid(GUEST_REGS *regs)
{
    // Magic Ophion leaf: when guest issues CPUID with eax=0x4F504849 ('IHPO')
    // we synthesize 'NHPO' + version + exit count instead of forwarding to HW.
    // Lets user-mode probe detect VMM presence without kernel driver. ASCII
    // round-trips intact in regs (little-endian).
    //
    // Phase 7a stealth: g_stealth_locked latches after lockdown trigger
    // (OPHX subleaf 0xFD). Once set, all magic leaves passthrough to bare
    // CPUID — anti-cheat probing OPHI/OPHR/OPHS/OPHX sees normal CPU
    // responses. VMCALL channel keeps working (dispatch is via patched
    // syscall, not CPUID).
    extern UINT32 g_stealth_locked;
    if (!g_stealth_locked) {
    if ((UINT32)regs->rax == 0x4F504849u) {  // 'OPHI'
        regs->rax = 0x4E48504Fu;             // 'OPHN'
        regs->rbx = 0x00020007u;             // version 2.7 (major=2 minor=7)
        regs->rcx = (UINT32)g_exit_count;
        regs->rdx = (UINT32)((__readmsr(0xC0000103) /* IA32_TSC_AUX */) & 0xFFF);
        return;
    }

    // Phase 4a magic leaf: 'OPHR' = 0x4F504852.
    // Resolves ntoskrnl base + KiServiceTable + NtCreateProfile via guest CR3.
    // Cached after first call. Subleaf in rcx selects field set.
    if ((UINT32)regs->rax == 0x4F504852u) {
        UINT64 cr3 = 0;
        __vmx_vmread(VMCS_GUEST_CR3, &cr3);
        ophion_resolve_all_once(cr3);
        UINT32 a = 0, b = 0, c = 0, d = 0;
        ophion_resolve_get((UINT32)regs->rcx, &a, &b, &c, &d);
        regs->rax = a;
        regs->rbx = b;
        regs->rcx = c;
        regs->rdx = d;
        return;
    }

    // Phase 4d-i magic leaf: 'OPHX' = 0x4F504858 (install patch).
    // ecx = 0xFF triggers install; 0/1/2/3 = status / inline_patch /
    // post_read / pre_read. Idempotent — install_attempted latched.
    // Phase 7a: subleaf 0xFD latches g_stealth_locked → all magic leaves
    // hereafter passthrough to bare CPUID.
    if ((UINT32)regs->rax == 0x4F504858u) {
        UINT64 cr3 = 0;
        __vmx_vmread(VMCS_GUEST_CR3, &cr3);
        UINT32 sub = (UINT32)regs->rcx;
        if (sub == 0xFF) {
            ophion_install_do(cr3);
            sub = 0;
        }
        // Phase 7d: subleaf 0xFE = cloaked install (alt page + EPT cloak).
        // Subleafs 0x80/0x81 read cloak install state.
        if (sub == 0xFE) {
            ophion_install_do_cloaked(cr3);
            sub = 0x80;  // fall through to read cloak status
        }
        if (sub == 0x80 || sub == 0x81) {
            UINT32 a = 0, b = 0, c = 0, d = 0;
            ophion_install_cloak_get(sub - 0x80, &a, &b, &c, &d);
            regs->rax = a;
            regs->rbx = b;
            regs->rcx = c;
            regs->rdx = d;
            return;
        }
        if (sub == 0xFD) {
            g_stealth_locked = 1;
            sub = 0;
        }
        UINT32 a = 0, b = 0, c = 0, d = 0;
        ophion_install_get(sub, &a, &b, &c, &d);
        regs->rax = a;
        regs->rbx = b;
        regs->rcx = c;
        regs->rdx = d;
        return;
    }

    // Phase 4a-x magic leaf: 'OPHS' = 0x4F504853 (set).
    // Cheat user-mode supplies NtCreateProfile RVA (32-bit, relative to
    // ntos_base) in ecx. VMM validates, body-prologue-checks via guest read,
    // caches into resolver state. Pivot from VMM-side scan that couldn't
    // disambiguate KiServiceTable from KiArgumentTable without PDB.
    if ((UINT32)regs->rax == 0x4F504853u) {
        UINT64 cr3 = 0;
        __vmx_vmread(VMCS_GUEST_CR3, &cr3);
        ophion_resolve_all_once(cr3);  // ensure ntos_base populated
        UINT32 rva = (UINT32)regs->rcx;
        UINT32 new_flags = ophion_resolve_set_ncp(cr3, rva);
        regs->rax = 0x4F504853u;
        UINT32 a = 0, b = 0, c = 0, d = 0;
        ophion_resolve_get(1, &a, &b, &c, &d);  // subleaf 1 = NCP VA + flags
        regs->rbx = b;
        regs->rcx = c;
        regs->rdx = new_flags;
        return;
    }
    } // end if (!g_stealth_locked)

    int cpu_info[4];
    UINT32 leaf = (UINT32)regs->rax;
    UINT32 sub  = (UINT32)regs->rcx;
    __cpuidex(cpu_info, (int)leaf, (int)sub);
    regs->rax = (UINT32)cpu_info[0];
    regs->rbx = (UINT32)cpu_info[1];
    regs->rcx = (UINT32)cpu_info[2];
    regs->rdx = (UINT32)cpu_info[3];

    // Phase 7c-1: HV-leak stealth (defensive clamp).
    //  Leaf 1 ECX bit 31 = Hypervisor-Present. Bare metal returns 0; under any
    //  HV layer this would be set. Vanguard CPUMODEL_BIT_HV_LEAF (VAN 116/118).
    //  Cheap belt-and-suspenders — passthrough already returns 0 on bare HW
    //  but firmware/microcode quirks could leak; mask it.
    //  Leaf 0x40000000 left passthrough: Alder Lake i5-12400F bare returns
    //  (eax=0 ebx=1 ecx=0 edx=0, no vendor string) which doesn't match any
    //  entry in vgk's kHvSignatures[] (verified via vgk_probe). See
    //  feedback_alder_lake_cpuid_quirk.md.
    if (leaf == 1) {
        regs->rcx &= ~(1ULL << 31);
    }
}

// Phase 7c-2: inject #GP(0) on out-of-bitmap MSR access in HV synthetic range
// (0x40000000-0x4FFFFFFF). Bare metal returns #GP for these. Without this,
// default branch logs + advances RIP — guest sees stale GPRs, no exception,
// trips Vanguard CPUMODEL_BIT_HV (VAN 117 manipulated MSRs).
static VOID
vmexit_inject_gp0(VOID)
{
    VMENTRY_INTERRUPT_INFORMATION info = {0};
    info.Vector           = EXCEPTION_VECTOR_GENERAL_PROTECTION;
    info.InterruptionType = INTERRUPT_TYPE_HARDWARE_EXCEPTION;
    info.DeliverErrorCode = 1;
    info.Valid            = 1;
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, info.AsUInt);
}

// VMCALL signature (matches AsmVmxOperation.asm asm_vmx_vmcall).
#define HVFS_SIG_R10  0x48564653ULL          // 'HVFS'
#define HVFS_SIG_R11  0x564d43414c4cULL      // 'VMCALL'
#define HVFS_SIG_R12  0x4e4f485950455256ULL  // 'NOHYPERV'

static BOOLEAN
vmcall_signature_ok(VOID)
{
    // Signatures live in r10/r11/r12 set by asm_vmx_vmcall before VMCALL.
    // The vmexit handler asm already pushed all GPRs; we read them by reading
    // the VMCS instead of trusting the GPR struct (asm pushes the values
    // *as they were before VMCALL*, so they're in regs).
    // For Phase 2 minimum, accept any VMCALL — signature checking comes when
    // VmcallHandler.c integrates.
    return TRUE;
}

BOOLEAN EFIAPI
vmexit_handler(IN GUEST_REGS *regs, IN VIRTUAL_MACHINE_STATE *vcpu)
{
    UINT64 exit_reason_full = 0;
    __vmx_vmread(VMCS_EXIT_REASON, &exit_reason_full);
    UINT16 exit_reason = (UINT16)(exit_reason_full & 0xFFFF);

    // Phase 7d-debug: bump per-reason histogram (clamped to 0..63).
    if (exit_reason < 64) {
        g_exit_hist[exit_reason]++;
    }

    // FIRST-ACTION telemetry: log the first 3 vmexit reasons before doing
    // anything else. Confirms control reached vmexit_handler at all + reveals
    // which exit reason is wedging. Only first 3 to bound flash wear.
    if (g_exit_count < 3) {
        UINT64 qualif = 0, gphys = 0, rip = 0;
        __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qualif);
        __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &gphys);
        __vmx_vmread(VMCS_GUEST_RIP, &rip);
        VmmLogVarSetf(L"OphnExit",
            "n=%u reason=0x%x qual=0x%llx gphys=0x%llx grip=0x%llx",
            g_exit_count, (UINT32)exit_reason, qualif, gphys, rip);
        g_exit_count++;
    }

    vcpu->exit_reason = exit_reason;
    vcpu->advance_rip = TRUE;

    // Step #8 (Grill Q21-C): per-CPU log ring. Lock-free; this CPU is the
    // sole writer of g_rings[vcpu->core_id]. Tag = full exit-reason word so
    // we can recover any modifier bits (vmexit-from-SMM etc.) post-mortem.
    {
        UINT64 qual_pcl = 0, rip_pcl = 0;
        __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual_pcl);
        __vmx_vmread(VMCS_GUEST_RIP, &rip_pcl);
        VmmPclRecord(vcpu->core_id, exit_reason, qual_pcl, rip_pcl,
                     (UINT32)(exit_reason_full & 0xFFFFFFFFULL));
    }

    // Phase 5a: latch VMM start TSC on first vmexit. Used by STATUS_QUERY
    // handler to report vmm_uptime_ms. Lazy so we don't need a post-launch
    // hook. First exit is typically the first CPUID issued by Windows boot.
    extern UINT64 g_vmm_start_tsc;
    if (g_vmm_start_tsc == 0) {
        g_vmm_start_tsc = __rdtsc();
    }

    // Phase 2.7: VMENTRY_FAILURE_GUEST_STATE (33/0x21) handler.
    // Phase 7c-4: VMENTRY_FAILURE_MSR_LOADING (34/0x22) handler — same
    // recovery (VMXOFF + halt). Reason 34 means hardware tried to load an
    // MSR from VMENTRY_MSR_LOAD list and the access #GP'd. Without handler,
    // BSP would loop vmresume forever -> reset. With it, BSP halts cleanly,
    // user F12 -> Windows Boot Manager -> restore previous ESP image.
    if (exit_reason == VMX_EXIT_REASON_VMENTRY_FAILURE_MSR_LOADING) {
        UINT64 qual = 0;
        __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);
        if (vcpu->core_id == 0) {
            VmmLogVarSetf(L"OphnMsrLoadFail",
                "core=%u msr_idx=%llu qualif=0x%llx",
                vcpu->core_id, qual, qual);
        }
        __vmx_off();
        for (;;) { __halt(); }
    }
    if (exit_reason == VMX_EXIT_REASON_VMENTRY_FAILURE_GUEST_STATE) {
        UINT64 g_cr0=0, g_cr3=0, g_cr4=0, g_dr7=0, g_rfl=0, g_rip=0;
        UINT64 g_cs=0, g_ss=0, g_ds=0, g_es=0, g_fs=0, g_gs=0, g_tr=0, g_ldtr=0;
        UINT64 g_csar=0, g_ssar=0, g_trar=0, g_ldar=0;
        UINT64 g_cslim=0, g_ssbase=0, g_csbase=0;
        UINT64 g_intst=0, g_actst=0;
        __vmx_vmread(VMCS_GUEST_CR0, &g_cr0);
        __vmx_vmread(VMCS_GUEST_CR3, &g_cr3);
        __vmx_vmread(VMCS_GUEST_CR4, &g_cr4);
        __vmx_vmread(VMCS_GUEST_DR7, &g_dr7);
        __vmx_vmread(VMCS_GUEST_RFLAGS, &g_rfl);
        __vmx_vmread(VMCS_GUEST_RIP, &g_rip);
        __vmx_vmread(VMCS_GUEST_CS_SELECTOR, &g_cs);
        __vmx_vmread(VMCS_GUEST_SS_SELECTOR, &g_ss);
        __vmx_vmread(VMCS_GUEST_DS_SELECTOR, &g_ds);
        __vmx_vmread(VMCS_GUEST_ES_SELECTOR, &g_es);
        __vmx_vmread(VMCS_GUEST_FS_SELECTOR, &g_fs);
        __vmx_vmread(VMCS_GUEST_GS_SELECTOR, &g_gs);
        __vmx_vmread(VMCS_GUEST_TR_SELECTOR, &g_tr);
        __vmx_vmread(VMCS_GUEST_LDTR_SELECTOR, &g_ldtr);
        __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &g_csar);
        __vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, &g_ssar);
        __vmx_vmread(VMCS_GUEST_TR_ACCESS_RIGHTS, &g_trar);
        __vmx_vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS, &g_ldar);
        __vmx_vmread(VMCS_GUEST_CS_LIMIT, &g_cslim);
        __vmx_vmread(VMCS_GUEST_CS_BASE, &g_csbase);
        __vmx_vmread(VMCS_GUEST_SS_BASE, &g_ssbase);
        __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &g_intst);
        __vmx_vmread(VMCS_GUEST_ACTIVITY_STATE, &g_actst);

        vcpu->vmentry_fail_seen++;

        // Only BSP writes NV vars (boot-time, single-threaded). AP vmexit
        // context post-EBS racing SetVariable with NT was the 3d-iii-b
        // 100% CPU cause — guard with core_id==0.
        if (vcpu->core_id == 0) {
            VmmLogVarSetf(L"OphnGS1",
                "cr0=%llx cr3=%llx cr4=%llx dr7=%llx rfl=%llx rip=%llx",
                g_cr0, g_cr3, g_cr4, g_dr7, g_rfl, g_rip);
            VmmLogVarSetf(L"OphnGS2",
                "cs=%x ss=%x ds=%x es=%x fs=%x gs=%x tr=%x ldtr=%x",
                (UINT32)g_cs, (UINT32)g_ss, (UINT32)g_ds, (UINT32)g_es,
                (UINT32)g_fs, (UINT32)g_gs, (UINT32)g_tr, (UINT32)g_ldtr);
            VmmLogVarSetf(L"OphnGS3",
                "csar=%x ssar=%x trar=%x ldar=%x cslim=%x csbase=%llx ssbase=%llx ist=%x ast=%x",
                (UINT32)g_csar, (UINT32)g_ssar, (UINT32)g_trar, (UINT32)g_ldar,
                (UINT32)g_cslim, g_csbase, g_ssbase,
                (UINT32)g_intst, (UINT32)g_actst);
        }

        // VMXOFF + halt this core. AP loses VMM but doesn't wedge NT — INIT
        // from NT pulls AP back to reset state native-side. BSP halt = boot
        // hang (intentional, user power-cycles to read NV log).
        __vmx_off();
        for (;;) { __halt(); }
    }

    switch (exit_reason) {
    case VMX_EXIT_REASON_EXECUTE_CPUID:
        handle_cpuid(regs);
        break;

    case VMX_EXIT_REASON_INIT_SIGNAL:
        // INIT IPI received in non-root. SDM 26.7.4: emulate INIT by setting
        // guest activity state = 3 (Wait-for-SIPI). RIP not advanced — exit
        // instruction length is undefined for INIT.
        // No NV writes from AP vmexit context (post-EBS SetVariable on AP
        // races NT's own var usage → undefined → 100% CPU thrash).
        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 3);
        vcpu->init_seen++;
        vcpu->advance_rip = FALSE;
        break;

    case VMX_EXIT_REASON_SIPI: {
        // SIPI vector in exit qualification low byte. Place guest in real-mode
        // at CS=vector<<8, IP=0, per SDM Vol 3 26.7.4 + Vol 3 9.4 reset state.
        UINT64 qual = 0;
        __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);
        UINT16 vec = (UINT16)(qual & 0xFF);

        // Real-mode CS: sel=vector<<8, base=vector<<12, limit=0xFFFF, AR=0x9B
        // (P=1, S=1, type=11). Other segs flat real-mode AR=0x93.
        __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR,      (UINT64)vec << 8);
        __vmx_vmwrite(VMCS_GUEST_CS_BASE,          (UINT64)vec << 12);
        __vmx_vmwrite(VMCS_GUEST_CS_LIMIT,         0xFFFFu);
        __vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, 0x9B);

        __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR,      0);
        __vmx_vmwrite(VMCS_GUEST_DS_BASE,          0);
        __vmx_vmwrite(VMCS_GUEST_DS_LIMIT,         0xFFFFu);
        __vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, 0x93);

        __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR,      0);
        __vmx_vmwrite(VMCS_GUEST_ES_BASE,          0);
        __vmx_vmwrite(VMCS_GUEST_ES_LIMIT,         0xFFFFu);
        __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, 0x93);

        __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR,      0);
        __vmx_vmwrite(VMCS_GUEST_FS_BASE,          0);
        __vmx_vmwrite(VMCS_GUEST_FS_LIMIT,         0xFFFFu);
        __vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, 0x93);

        __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR,      0);
        __vmx_vmwrite(VMCS_GUEST_GS_BASE,          0);
        __vmx_vmwrite(VMCS_GUEST_GS_LIMIT,         0xFFFFu);
        __vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, 0x93);

        __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR,      0);
        __vmx_vmwrite(VMCS_GUEST_SS_BASE,          0);
        __vmx_vmwrite(VMCS_GUEST_SS_LIMIT,         0xFFFFu);
        __vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, 0x93);

        __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR,      0);
        __vmx_vmwrite(VMCS_GUEST_LDTR_BASE,          0);
        __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT,         0xFFFF);
        __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0x82);

        __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR,      0);
        __vmx_vmwrite(VMCS_GUEST_TR_BASE,          0);
        __vmx_vmwrite(VMCS_GUEST_TR_LIMIT,         0xFFFF);
        __vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, 0x8B);

        __vmx_vmwrite(VMCS_GUEST_RIP,    0);
        __vmx_vmwrite(VMCS_GUEST_RSP,    0);
        __vmx_vmwrite(VMCS_GUEST_RFLAGS, 0x2);

        // CR0: PE=PG=0 base + NW/CD/ET (post-reset), then apply VMX fixed bits.
        // SDM 26.8: with UNRESTRICTED_GUEST, FIXED0 bits PE (0) and PG (31) are
        // NOT required; all other FIXED0 bits MUST be set (notably NE bit 5
        // on Alder Lake — was missing in 3d-iii-b → VMENTRY fail reason 33).
        UINT64 cr0_fix0 = __readmsr(IA32_VMX_CR0_FIXED0);
        UINT64 cr0_fix1 = __readmsr(IA32_VMX_CR0_FIXED1);
        UINT64 cr0_required_under_ug = cr0_fix0 & ~((1ULL << 0) | (1ULL << 31));
        UINT64 cr0_real = (0x60000010ULL | cr0_required_under_ug) & cr0_fix1;
        __vmx_vmwrite(VMCS_GUEST_CR0,             cr0_real);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW,  cr0_real);

        // CR4: clear PAE, retain VMXE (VMX FIXED0 forces it). Apply fixed bits.
        // Read shadow=0 hides VMXE from guest probes.
        UINT64 cr4_fix0 = __readmsr(IA32_VMX_CR4_FIXED0);
        UINT64 cr4_fix1 = __readmsr(IA32_VMX_CR4_FIXED1);
        UINT64 cr4_real = ((__readcr4() & ~0x20ULL) | cr4_fix0) & cr4_fix1;
        __vmx_vmwrite(VMCS_GUEST_CR4,             cr4_real);
        __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW,  0);

        __vmx_vmwrite(VMCS_GUEST_CR3, 0);

        // EFER: clear LMA + LME so guest is in legacy real-mode.
        __vmx_vmwrite(VMCS_GUEST_EFER, 0);

        // VM-entry controls: clear IA32E_MODE_GUEST so VMENTRY does not force
        // long mode.
        UINT64 entry_ctrls = 0;
        __vmx_vmread(VMCS_CTRL_VMENTRY_CONTROLS, &entry_ctrls);
        entry_ctrls &= ~(UINT64)VM_ENTRY_CTRL_IA32E_MODE_GUEST;
        __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, entry_ctrls);

        // Activity state Active (0).
        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);

        // Per-vcpu in-memory log only (no NV write from AP vmexit context).
        vcpu->sipi_seen++;
        vcpu->last_sipi_vec = vec;

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_VMCALL: {
        // Phase 4e: Ophion VMCALL dispatch. Trampoline shuffled args before
        // VMCALL so:
        //   rcx = OPHION_VMCALL_MAGIC_HANDLE (auth marker)
        //   rax = session_key (set by cheat exe; 0 for REGISTER op)
        //   rdx = op_code
        //   r8  = caller buffer VA in cheat process
        //   r9  = caller buffer size
        //
        // Dispatch path:
        //   1. Read caller_cr3 + caller_rip from VMCS for 3-factor auth.
        //   2. PT-walk r8 buffer into VMM scratch via vmm_guest_read.
        //   3. Call VmcallDispatch (validates op, services request).
        //   4. Write response (in scratch) back to caller via vmm_guest_write.
        //   5. Set rax = status, RIP advances 3 bytes (default).
        if (regs->rcx == OPHION_VMCALL_MAGIC_HANDLE_U64) {
            static UINT8 scratch[OPHION_VMCALL_SCRATCH_BYTES];

            UINT64 caller_rip = 0, caller_cr3 = 0;
            __vmx_vmread(VMCS_GUEST_RIP, &caller_rip);
            __vmx_vmread(VMCS_GUEST_CR3, &caller_cr3);

            // Phase 5e: caller_rip must be inside our trampoline page. Magic
            // handle alone is insufficient — anyone who reads OPHR sub 8 can
            // discover trampoline_va and craft a direct VMCALL. RIP gate
            // ensures only the trampoline path reaches dispatch.
            if (g_trampoline_built && g_trampoline_va != 0 &&
                (caller_rip < g_trampoline_va ||
                 caller_rip >= g_trampoline_va + g_trampoline_size)) {
                g_vmcall_rip_rejects++;
                g_vmcall_last_bad_rip = caller_rip;
                vmexit_inject_ud();
                vcpu->advance_rip = FALSE;
                break;
            }

            UINT64 buf_va = regs->r8;
            UINT32 buf_sz = (UINT32)regs->r9;

            UINT32 status = OPHION_STATUS_INVALID_ARG;
            // UNREGISTER takes no buffer (size=0, ptr=NULL is legal). All
            // other ops require a buffer fitting in scratch.
            if ((UINT32)regs->rdx == OPHION_OP_UNREGISTER && buf_sz == 0) {
                status = VmcallDispatch(regs->rax,
                                        (UINT32)regs->rdx,
                                        NULL,
                                        0,
                                        caller_rip,
                                        caller_cr3);
            } else if (buf_sz > 0 && buf_sz <= OPHION_VMCALL_SCRATCH_BYTES) {
                UINTN got = vmm_guest_read(caller_cr3, buf_va, scratch, buf_sz);
                if (got == buf_sz) {
                    status = VmcallDispatch(regs->rax,
                                            (UINT32)regs->rdx,
                                            scratch,
                                            buf_sz,
                                            caller_rip,
                                            caller_cr3);
                    vmm_guest_write(caller_cr3, buf_va, scratch, buf_sz);
                }
            }
            regs->rax = status;
            // RIP auto-advances 3 (vmcall length). vcpu->advance_rip = TRUE
            // by default; leave it alone.
            break;
        }

        // Legacy VMXOFF VMCALL (asm_vmx_vmcall with HVFS sig).
        if (vmcall_signature_ok() && regs->rcx == VMCALL_VMXOFF) {
            vcpu->advance_rip = FALSE;
            return TRUE;
        }
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDMSR:
    case VMX_EXIT_REASON_EXECUTE_WRMSR: {
        // Phase 7c-2: HV-synthetic MSR stealth. Bitmap covers 0-0x1FFF +
        // 0xC0000000-0xC0001FFF; any RDMSR/WRMSR outside those forces a
        // vmexit. For HV synthetic range (0x40000000-0x4FFFFFFF, e.g.
        // HV_X64_MSR_GUEST_OS_ID, HV_X64_MSR_HYPERCALL) bare metal raises
        // #GP(0). Match it. Mitigates Vanguard VAN 117.
        // Other out-of-bitmap MSRs: keep default log+advance (Phase 2.7
        // boot path proven safe with that).
        UINT32 msr_idx = (UINT32)regs->rcx;
        if (msr_idx >= 0x40000000u && msr_idx <= 0x4FFFFFFFu) {
            vmexit_inject_gp0();
            vcpu->advance_rip = FALSE;
        } else {
            hv_log("[hv] msr exit msr=0x%x reason=%u rip=passthrough\n",
                   msr_idx, exit_reason);
        }
        break;
    }

    case VMX_EXIT_REASON_EPT_VIOLATION: {
        // Phase 7d step 3: cloak read-view swap.
        // Exit qualification bits (Intel SDM 28.2.1):
        //   bit 0 = read   bit 1 = write   bit 2 = instruction fetch
        // Exec-only PML1 (R=0 W=0 X=1) gets violation only on read/write.
        // Swap to read-view (real_pfn R=1 W=1 X=0), arm MTF, INVEPT single,
        // resume guest. MTF handler swaps back next instruction.
        UINT64 qual = 0, gphys = 0;
        __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);
        __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &gphys);

        UINT64 alt_pfn = 0;
        VOID *pml1 = NULL;
        if (ept_cloak_violation_swap_to_read(gphys, &alt_pfn, &pml1)) {
            vcpu->mtf_pending_restore = TRUE;
            vcpu->mtf_pml1            = pml1;
            vcpu->mtf_alt_pfn         = alt_pfn;
            ept_set_mtf();
            ept_invept_single(ept_get_eptp_bsp());
            g_ept_violation_cloaks++;
        } else {
            // Non-cloak EPT violation = unexpected; log and resume without
            // RIP advance (faulting insn will retry).
            g_ept_violation_other++;
        }
        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_MONITOR_TRAP_FLAG: {
        // Phase 7d step 4: post-step cloak restore. Guest just executed one
        // instruction with read-view exposed; flip back to exec-only and
        // disarm MTF. INVEPT to flush the read-view TLB entry.
        if (vcpu->mtf_pending_restore) {
            ept_cloak_mtf_swap_to_exec(vcpu->mtf_pml1, vcpu->mtf_alt_pfn);
            ept_invept_single(ept_get_eptp_bsp());
            vcpu->mtf_pending_restore = FALSE;
            vcpu->mtf_pml1            = NULL;
            vcpu->mtf_alt_pfn         = 0;
            g_mtf_restores++;
        }
        ept_clear_mtf();
        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_TRIPLE_FAULT:
        hv_log("[hv] triple fault on core %u — halting\n", vcpu->core_id);
        for (;;) { __halt(); }

    default:
        // Phase 7d-debug: NV-stamp first-ever unhandled reason BEFORE log
        // so post-freeze reboot reveals what wedged. Only stamp once
        // (g_first_bad_reason latch). Subsequent unhandled exits silent.
        if (g_first_bad_reason == 0xFFFF) {
            g_first_bad_reason = exit_reason;
            UINT64 grip = 0, qual = 0;
            __vmx_vmread(VMCS_GUEST_RIP, &grip);
            __vmx_vmread(VMCS_EXIT_QUALIFICATION, &qual);
            // Single-shot NV write. If freeze hangs flash mid-write, NV is
            // already journaled — we'll see it next boot.
            VmmLogVarSetf(L"OphnFirstBad",
                "reason=%u qual=0x%llx grip=0x%llx core=%u",
                (UINT32)exit_reason, qual, grip, vcpu->core_id);
        }
        // Best-effort fall-through: advance RIP + vmresume. Drop hv_log
        // (Print to dead ConOut post-EBS = freeze).
        break;
    }

    if (vcpu->advance_rip)
        vmexit_advance_rip();

    return FALSE;
}

// Minimal #UD injection for unrecognised VMCALL.
VOID
vmexit_inject_ud(VOID)
{
    VMENTRY_INTERRUPT_INFORMATION info = {0};
    info.Vector           = EXCEPTION_VECTOR_UNDEFINED_OPCODE;
    info.InterruptionType = INTERRUPT_TYPE_HARDWARE_EXCEPTION;
    info.DeliverErrorCode = 0;
    info.Valid            = 1;
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, info.AsUInt);
}
