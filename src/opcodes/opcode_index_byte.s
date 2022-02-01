	include "defines.s"

	org $0

	; A := A + S0; P := P + 1
INST_INDEX_BYTE:
	move.l (sp)+,d0
	move.l (sp)+,d1
	add.l d1,d0
	move.l d0,-(sp)