	include "defines.s"

	org $0

INST_XOR:
	move.l (sp)+,d0
	move.l (sp)+,d1
	eor.l d1,d0
	move.l d0,-(sp)