	include "defines.s"

	org $0

INST_MUL:
	move.l (sp)+,d0
	move.l (sp)+,d1
	jsr ADDRESS
	move.l d0,-(sp)
