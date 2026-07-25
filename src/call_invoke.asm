; Microsoft x64 invoker for hdllib.
; uint64_t HdlInvokeX64(void* fn, const uint64_t* gpr, const uint64_t* xmm,
;                       const uint64_t* stack_args, uint32_t stack_count);

OPTION CASEMAP:NONE

_TEXT SEGMENT

PUBLIC HdlInvokeX64

HdlInvokeX64 PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14

    ; RCX=fn RDX=gpr R8=xmm R9=stack_args  [rbp+30h]=stack_count
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov rsi, r9
    mov ebx, dword ptr [rbp+30h]

    ; After 7 pushes, rsp is 16-byte aligned. Allocate shadow+stack (multiple of 16).
    mov eax, ebx
    lea eax, [eax*8+20h]
    add eax, 0Fh
    and eax, 0FFFFFFF0h
    sub rsp, rax

    test ebx, ebx
    jz load_regs
    mov ecx, ebx
    lea rdi, [rsp+20h]
    mov rdx, rsi
copy_stack:
    mov rax, qword ptr [rdx]
    mov qword ptr [rdi], rax
    add rdx, 8
    add rdi, 8
    dec ecx
    jnz copy_stack

load_regs:
    movsd xmm0, qword ptr [r14]
    movsd xmm1, qword ptr [r14+8]
    movsd xmm2, qword ptr [r14+10h]
    movsd xmm3, qword ptr [r14+18h]

    mov rcx, qword ptr [r13]
    mov rdx, qword ptr [r13+8]
    mov r8,  qword ptr [r13+10h]
    mov r9,  qword ptr [r13+18h]

    call r12

    lea rsp, [rbp-30h]
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
HdlInvokeX64 ENDP

_TEXT ENDS
END
