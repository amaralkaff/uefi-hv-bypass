; AsmRelayCall.asm
;
; Two paths from driver into VMCALL dispatcher:
;
;   1. OphionRelayCallTrampoline  -- jumps through NtCreateProfile inline
;      patch into the runtime trampoline page that NtosBuildTrampoline emits.
;      Used when VMM has built the trampoline (g_trampoline_built == 1) and
;      the inline jmp is in NtCreateProfile.  The trampoline shuffles the
;      Win64 argument registers into the VMM ABI and issues VMCALL.
;
;   2. OphionRelayCallDirect      -- bridge-mode bypass.  Issues VMCALL
;      directly from the driver with the magic handle in rcx and the VMM
;      ABI laid out in rax/rdx/r8/r9.  VMM's vmexit handler accepts this
;      whenever g_trampoline_built == 0 (RIP-range gate disabled until the
;      trampoline is actually built); see MongilLoader/OphionDxe/VmmExit.c
;      Phase 5e block.  Used by the bridge driver while we don't drive the
;      OPHS RVA-set magic leaf and the VMM has never populated the
;      trampoline page (it stays 0xCC int3 fill).  This is the canonical
;      bridge path -- driver runs in system context, RIP discipline is
;      already enforced by the kernel-mode privilege check.
;
; Both paths return UINT64 in rax = VMCALL status.

PUBLIC OphionRelayCallTrampoline
PUBLIC OphionRelayCallDirect

.code _text

; UINT64 OphionRelayCallTrampoline(
;   UINT64 trampoline_va,   /* rcx */
;   UINT64 session_key,     /* rdx */
;   UINT64 op,              /* r8  */
;   UINT64 buf_va,          /* r9  */
;   UINT64 buf_size);       /* [rsp+0x28] */
;
; The trampoline expects:
;   rcx = OPHION_VMCALL_MAGIC_HANDLE  (0xCAFEDEADBEEF1234)
;   rdx = session_key
;   r8  = op
;   r9  = buf_va
;   [rsp+0x28] = buf_size
;
; Trampoline shuffles regs (rax<-rdx, rdx<-r8, r8<-r9, r9<-[rsp+0x28]),
; emits VMCALL, then RET.  We jmp (not call) so trampoline's RET pops
; the return address pushed by our caller and returns directly there
; with rax = VMCALL result.

OphionRelayCallTrampoline PROC
    mov     rax, rcx                        ; save trampoline VA
    mov     rcx, 0CAFEDEADBEEF1234h         ; magic
    jmp     rax                             ; tail-call
OphionRelayCallTrampoline ENDP

; UINT64 OphionRelayCallDirect(
;   UINT64 session_key,     /* rcx */
;   UINT64 op,              /* rdx */
;   UINT64 buf_va,          /* r8  */
;   UINT64 buf_size);       /* r9  */
;
; Lays out the VMM ABI in registers (no stack arg) and issues VMCALL.
;
;   rcx = OPHION_VMCALL_MAGIC_HANDLE
;   rax = session_key
;   rdx = op
;   r8  = buf_va
;   r9  = buf_size
;
; VMM's vmexit handler reads rcx for the magic match, then dispatches
; using the rax/rdx/r8/r9 layout above (matches what the trampoline
; produces post-shuffle).  After VMRESUME, rax holds the VMCALL status.

OphionRelayCallDirect PROC
    mov     rax, rcx                        ; rax = session_key
    mov     rcx, 0CAFEDEADBEEF1234h         ; rcx = magic
    db      0Fh, 01h, 0C1h                  ; vmcall
    ret
OphionRelayCallDirect ENDP

END
