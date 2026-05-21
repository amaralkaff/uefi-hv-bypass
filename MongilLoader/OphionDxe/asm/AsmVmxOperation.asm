; AsmVmxOperation.asm - VMX enable, VMCALL interface
; Ported verbatim from Ophion/asm/AsmVmxOperation.asm. No Windows deps.

PUBLIC asm_enable_vmx
PUBLIC asm_vmx_vmcall

.code

asm_enable_vmx PROC
    xor     rax, rax
    mov     rax, cr4
    or      rax, 02000h         ; Set bit 13 (VMXE)
    mov     cr4, rax
    ret
asm_enable_vmx ENDP

; asm_vmx_vmcall(UINT64 vmcall_num /*rcx*/, UINT64 param1 /*rdx*/,
;                UINT64 param2 /*r8*/, UINT64 param3 /*r9*/)
; Sets signature registers R10/R11/R12 so VM-exit handler can
; verify this VMCALL came from our code. Returns NTSTATUS in RAX.
asm_vmx_vmcall PROC
    pushfq

    push    r10
    push    r11
    push    r12

    mov     r10, 48564653h          ; 'HVFS' signature
    mov     r11, 564d43414c4ch      ; 'VMCALL' signature
    mov     r12, 4e4f485950455256h  ; 'NOHYPERV' signature

    vmcall

    pop     r12
    pop     r11
    pop     r10

    popfq
    ret
asm_vmx_vmcall ENDP

END
