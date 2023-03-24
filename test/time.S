.text
.align 2
.globl _mytime
_mytime:
	mov	w16, #-3
	svc	#0x80
	ret
