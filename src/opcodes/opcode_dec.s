	include "defines.s"

	org $0

	; [A] := [A] - 1, A := [A]
INST_DEC:
	move.l (sp)+,a5
	subq.l #1,(a5)