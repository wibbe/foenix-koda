	org $0

MEMCOPY:
	move.l (12,sp),a0 			; fetch destination pointer
	move.l (8,sp),a1			; fetch source pointer
	move.l (4,sp),d1			; fetch byte count to copy
.memcopy_loop:
	move.b (a1)+,(a0)+
	dbra d1,.memcopy_loop
	rts