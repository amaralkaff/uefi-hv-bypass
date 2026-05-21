; AsmRelayCall.asm
; Tail-call into NtCreateProfile trampoline with magic in rcx.
;
; The trampoline (built by NtosBuildTrampoline in MongilLoader/OphionDxe/NtosPatch.c)
; expects:
;   rcx = OPHION_VMCALL_MAGIC_HANDLE  (0xCAFEDEADBEEF1234)
;   rdx = session_key
;   r8  = op
;   r9  = buf_va
;   [rsp+0x28] = buf_size
;
; Trampoline shuffles regs (rax<-rdx, rdx<-r8, r8<-r9, r9<-[rsp+0x28]),
; emits VMCALL, then RET. We jmp (not call) so trampoline's RET pops
; the return address pushed by our caller and returns directly there
; with rax = VMCALL result.

PUBLIC OphionRelayCallTrampoline

.code _text

; UINT64 OphionRelayCallTrampoline(
;   UINT64 trampoline_va,   /* rcx */
;   UINT64 session_key,     /* rdx */
;   UINT64 op,              /* r8  */
;   UINT64 buf_va,          /* r9  */
;   UINT64 buf_size);       /* [rsp+0x28] */

OphionRelayCallTrampoline PROC
    mov     rax, rcx                        ; save trampoline VA
    mov     rcx, 0CAFEDEADBEEF1234h         ; magic
    jmp     rax                             ; tail-call; trampoline RET returns to our caller
OphionRelayCallTrampoline ENDP

END
