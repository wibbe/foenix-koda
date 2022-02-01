	include "defines.s"

	org $0

INST_OR:
	move.l (sp)+,d0
	or.l (sp)+,d0
	move.l d0,-(sp)