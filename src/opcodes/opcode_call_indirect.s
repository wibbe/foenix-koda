	include "defines.s"

	org $0

INST_CALL_INDIRECT:
	move.l (sp)+,a5
	jsr (a5)