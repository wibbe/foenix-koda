	include "defines.s"

	org $0

INST_LOAD_GLOBAL_ADDR:
	move.l #ADDRESS,-(sp)
