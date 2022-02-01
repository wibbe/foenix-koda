	include "defines.s"

	org $0

INST_PEEK32:
	move.l (sp)+,a5
	move.w (a5),-(sp)
