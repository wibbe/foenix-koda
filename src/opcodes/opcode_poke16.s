	include "defines.s"

	org $0

INST_POKE8:
	move.l (sp)+,a5
	move.l (sp)+,a0
	move.w d0,(a5)