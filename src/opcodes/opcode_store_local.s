	include "defines.s"

	org $0

INST_STORE_LOCAL:
	move.l (sp)+,d0
	move.l d0,WORD_VALUE(a6)
