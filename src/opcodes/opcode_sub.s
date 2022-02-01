	include "defines.s"

	org $0

INST_SUB:
	move.l (sp)+,d0
	move.l (sp)+,d1
	sub.l d0,d1
	move.l d1,-(sp)
