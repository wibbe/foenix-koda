	include "defines.s"

	org $0

	; [A] := [A] + 1, A := [A]
INST_INC:
	move.l (sp)+,a5
	addq.l #1,(a5)