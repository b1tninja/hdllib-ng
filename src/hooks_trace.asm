; Gateway for MinHook capture stubs.
; On entry: r11 = TraceContext*, original args in rcx/rdx/r8/r9 and stack.
; Caller return address is at [rsp] before the frame setup.
; Calls HdlTraceCapture(ctx, caller, a0..a7) and returns its result in rax.

OPTION CASEMAP:NONE

EXTERN HdlTraceCapture:PROC

_TEXT SEGMENT

PUBLIC HdlTraceEntry

HdlTraceEntry PROC
    ; Save caller RA before allocating frame (currently at [rsp]).
    mov rax, qword ptr [rsp]

    sub rsp, 78h
    mov qword ptr [rsp+20h], rcx
    mov qword ptr [rsp+28h], rdx
    mov qword ptr [rsp+30h], r8
    mov qword ptr [rsp+38h], r9
    mov qword ptr [rsp+60h], rax ; caller

    ; Original stack args a4..a7 at caller [rsp+28h..] before this sub;
    ; current rsp = old_rsp - 78h => a4 at [rsp+78h+28h] = [rsp+0A0h]
    mov rax, qword ptr [rsp+0A0h]
    mov qword ptr [rsp+40h], rax
    mov rax, qword ptr [rsp+0A8h]
    mov qword ptr [rsp+48h], rax
    mov rax, qword ptr [rsp+0B0h]
    mov qword ptr [rsp+50h], rax
    mov rax, qword ptr [rsp+0B8h]
    mov qword ptr [rsp+58h], rax

    mov rcx, r11
    mov rdx, qword ptr [rsp+60h] ; caller
    mov r8,  qword ptr [rsp+20h] ; a0
    mov r9,  qword ptr [rsp+28h] ; a1
    ; stack: a2, a3, a4, a5, a6, a7
    mov rax, qword ptr [rsp+30h]
    mov qword ptr [rsp+20h], rax
    mov rax, qword ptr [rsp+38h]
    mov qword ptr [rsp+28h], rax
    mov rax, qword ptr [rsp+40h]
    mov qword ptr [rsp+30h], rax
    mov rax, qword ptr [rsp+48h]
    mov qword ptr [rsp+38h], rax
    mov rax, qword ptr [rsp+50h]
    mov qword ptr [rsp+40h], rax
    mov rax, qword ptr [rsp+58h]
    mov qword ptr [rsp+48h], rax

    call HdlTraceCapture
    add rsp, 78h
    ret
HdlTraceEntry ENDP

_TEXT ENDS
END
