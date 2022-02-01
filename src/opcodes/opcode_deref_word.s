	include "defines.s"

	org $0

	; A := [A]
INST_DEREF_WORD:
	move.l (sp)+,a5
	move.l (a5),-(sp)