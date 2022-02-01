	include "defines.s"

	org $0

INST_PEEK8:
	move.l (sp)+,a5
	moveq #0,d0
	move.b (a5),d0
	move.l d0,-(sp)