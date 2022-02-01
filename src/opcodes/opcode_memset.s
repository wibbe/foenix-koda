	org $0

MEMSET:
	move.l (4,sp),d1 			; copy length
	move.l (8,sp),d2 			; copy value to set to
	move.l (12,sp),a0			; copy pointer to byte data
.memset_loop:
	move.b d2,(a0)+
	dbra d1,.memset_loop
	rts