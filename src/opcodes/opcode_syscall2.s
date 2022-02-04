	org $0
	
SYSCALL2:
	move.l (4,sp),d2
	move.l (8,sp),d1
	move.l (12,sp),d0
	trap #15
	move.l d0,d6
	rts
