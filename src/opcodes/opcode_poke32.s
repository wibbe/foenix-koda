	include "defines.s"

	org $0

INST_POKE32:
	move.l (sp)+,a5
	move.l (sp)+,a0
	move.l d0,(a5)