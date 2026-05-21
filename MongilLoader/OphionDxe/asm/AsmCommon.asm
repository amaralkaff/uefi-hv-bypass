; AsmCommon.asm - common assembly routines
; Ported verbatim from Ophion/asm/AsmCommon.asm. No Windows-kernel deps.

PUBLIC asm_get_rflags
PUBLIC asm_reload_gdtr
PUBLIC asm_reload_idtr
PUBLIC asm_reload_tr
PUBLIC asm_write_cr2

.code

asm_get_rflags PROC
    pushfq
    pop     rax
    ret
asm_get_rflags ENDP

asm_reload_gdtr PROC
    push    rcx
    shl     rdx, 48
    push    rdx
    lgdt    fword ptr [rsp+6]
    pop     rax
    pop     rax
    ret
asm_reload_gdtr ENDP

asm_reload_idtr PROC
    push    rcx
    shl     rdx, 48
    push    rdx
    lidt    fword ptr [rsp+6]
    pop     rax
    pop     rax
    ret
asm_reload_idtr ENDP

asm_reload_tr PROC
    ltr     cx
    ret
asm_reload_tr ENDP

asm_write_cr2 PROC
    mov     cr2, rcx
    ret
asm_write_cr2 ENDP

END
