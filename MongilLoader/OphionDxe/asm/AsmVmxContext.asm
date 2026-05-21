; AsmVmxContext.asm - save/restore guest state around VMLAUNCH
; Ported verbatim from Ophion/asm/AsmVmxContext.asm.
; vmx_virtualize_cpu must be defined in C (currently in VmmStubs.c).

PUBLIC asm_vmx_save_state
PUBLIC asm_vmx_restore_state

EXTERN vmx_virtualize_cpu:PROC

.code

; asm_vmx_save_state
; Saves all GP registers + RFLAGS, then calls vmx_virtualize_cpu(RSP).
; On successful VMLAUNCH execution resumes at asm_vmx_restore_state
; (set as guest RIP in VMCS).
asm_vmx_save_state PROC

    push    0               ; Alignment padding (keep 16-byte aligned stack)

    pushfq

    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    sub     rsp, 0100h      ; Shadow space + scratch

    mov     rcx, rsp        ; arg1: current RSP = guest_stack
    call    vmx_virtualize_cpu

    ; If we reach here VMLAUNCH failed (rax = FALSE).
    ; Fall through to asm_vmx_restore_state to unwind the stack.
    jmp     asm_vmx_restore_state

asm_vmx_save_state ENDP

; asm_vmx_restore_state
; Guest RIP is set to this address in VMCS. On successful VMLAUNCH,
; CPU resumes here as if vmx_virtualize_cpu had returned.
asm_vmx_restore_state PROC

    add     rsp, 0100h

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    popfq

    add     rsp, 08h        ; alignment padding

    ret

asm_vmx_restore_state ENDP

END
