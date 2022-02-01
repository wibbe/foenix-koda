	include "defines.s"

	org $0

INST_DIV:
	move.l (sp)+,d0
	move.l (sp)+,d1
	jsr ADDRESS
	move.l d1,-(sp)
