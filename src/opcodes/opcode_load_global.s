	include "defines.s"

	org $0

INST_LOAD_GLOBAL:
	move.l ADDRESS,-(sp)
