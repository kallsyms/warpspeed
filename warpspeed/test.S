mov x0, #0xdead0000
msr VBAR_EL1, x0
mov x0, #0xff
msr MAIR_EL1, x0
movz x0, #0x1, lsl 32
movk x0, #0xb519, lsl 16
movk x0, #0x3519
msr TCR_EL1, x0
mov x0, #0x410000
msr TTBR0_EL1, x0
msr TTBR1_EL1, x0
isb
mrs x0, SCTLR_EL1
orr x0, x0, 1
msr SCTLR_EL1, x0
isb
