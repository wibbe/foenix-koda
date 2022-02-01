	include "defines.s"

	org $0

INST_CLEAR:
	moveq #0,d0
	move.l d0,-(sp)
