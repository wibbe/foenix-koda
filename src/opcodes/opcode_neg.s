	include "defines.s"

	org $0

INST_NEG:
	move.l (sp)+,d0
	neg.l d0
	move.l d0,-(sp)