	org $0

SYSCALL0:
	move.l (4,sp),d0
	trap #15
	rts
