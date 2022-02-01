	include "defines.s"

	org $0

	; A := 4 * A + S0; P := P + 1
INST_INDEX_WORD:
	move.l (sp)+,d0
	move.l (sp)+,d1
	lsl.l #2,d0
	add.l d1,d0
	move.l d0,-(sp)