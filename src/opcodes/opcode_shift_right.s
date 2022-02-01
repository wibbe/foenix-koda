	include "defines.s"

	org $0

	; A := S0 div 2A; P := P + 1 (r ight shift)
INST_SHIFT_RIGHT:
	move.l (sp)+,d1
	move.l (sp)+,d0
	lsr.l d0,d1
	move.l d1,-(sp)