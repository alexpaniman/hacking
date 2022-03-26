format ELF64

section '.text'

extrn 'puts' as _puts
puts = PLT _puts

extrn ceasar_encrypt

extrn string_copy
extrn asm_printf

extrn grant_access_string

access_buffer_size = 64

public grant_access
grant_access:	
    sub rsp, access_buffer_size

    mov rdi, rsp
    lea rsi, [grant_access_string]
    call string_copy

    mov rdi, rsp
    mov rsi, rsp
    mov rdx, [grant_access_string + 0x8]
    neg rdx
    call ceasar_encrypt

    mov rdi, rsp
    call puts

    add rsp, access_buffer_size

    ret
