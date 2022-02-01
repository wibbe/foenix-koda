	include "defines.s"

	org $0

INST_LOAD_LOCAL_ADDR:
	move.l a6,d0
	add.l #LONG_VALUE,d0
	move.l d0,-(sp)