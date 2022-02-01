	include "defines.s"

	org $0

INST_AND:
	move.l (sp)+,d0
	and.l (sp)+,d0
	move.l d0,-(sp)