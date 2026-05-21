; AsmHostIdt.asm - private host IDT handlers for VMX-root mode
; Ported from Ophion/asm/AsmHostIdt.asm.
; g_host_nmi_pending storage defined in C (VmmStubs.c).

PUBLIC asm_host_nmi_handler
PUBLIC asm_host_df_handler
PUBLIC asm_host_gp_handler
PUBLIC asm_host_default_handler

EXTERN g_host_nmi_pending:DWORD

.code

; NMI handler — sets per-cpu pending flag, vmexit handler injects to guest.
asm_host_nmi_handler PROC

    push    rax
    push    rcx

    ; cpu id from IA32_TSC_AUX (no memory access)
    mov     ecx, 0C0000103h
    rdmsr
    and     eax, 0FFFh

    lea     rcx, g_host_nmi_pending
    mov     dword ptr [rcx + rax*4], 1

    pop     rcx
    pop     rax
    iretq

asm_host_nmi_handler ENDP

; #DF in host = unrecoverable; halt.
asm_host_df_handler PROC
    cli
    hlt
    jmp     $
asm_host_df_handler ENDP

; #GP in host = bug; halt.
asm_host_gp_handler PROC
    cli
    hlt
    jmp     $
asm_host_gp_handler ENDP

; Catch-all unexpected vector; halt.
asm_host_default_handler PROC
    cli
    hlt
    jmp     $
asm_host_default_handler ENDP

END
