	include "defines.s"

	org $0

INST_HALT:
	move.l #LONG_VALUE,d1
	clr.l d0
	trap #15