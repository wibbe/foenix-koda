	include "defines.s"

	org $0

	; A := S0 ⋅ 2A; P := P + 1 (left shift)
INST_SHIFT_LEFT:
	move.l (sp)+,d1
	move.l (sp)+,d0
	lsl.l d0,d1
	move.l d1,-(sp)