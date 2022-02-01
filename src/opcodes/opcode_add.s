	include "defines.s"

	org $0

INST_ADD:
	move.l (sp)+,d0
	add.l (sp)+,d0
	move.l d0,-(sp)