	org $0

MAX:
	move.l (4,sp),d1
	move.l (8,sp),d2
	cmp d1,d2
	ble .max_d1 		; d1 >= d2
	move.l d2,d0
	bra .max_done
.max_d1:
	move.l d1,d0
.max_done:
	rts
