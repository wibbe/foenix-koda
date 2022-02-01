	org $0
	
SYSCALL1:
	move.l (4,sp),d1
	move.l (8,sp),d0
	trap #15
	rts
