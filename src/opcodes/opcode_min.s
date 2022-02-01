	org $0

MIN:
	move.l (4,sp),d1
	move.l (8,sp),d2
	cmp d1,d2
	ble .min_d2 		; d1 >= d2
	move.l d1,d0
	bra .min_done
.min_d2:
	move.l d2,d0
.min_done:
	rts