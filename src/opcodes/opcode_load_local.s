	include "defines.s"

	org $0

INST_LOAD_LOCAL:
	move.l WORD_VALUE(a6),-(sp)
