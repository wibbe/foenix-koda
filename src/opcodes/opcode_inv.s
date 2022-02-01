	include "defines.s"

	org $0

INST_INV:
	move.l (sp)+,d0
	not.l d0
	move.l d0,-(sp)