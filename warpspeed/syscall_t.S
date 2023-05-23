.global _syscall_t
.align 4

_syscall_t:
    mov x16, x8
    svc #0x80
    ret
