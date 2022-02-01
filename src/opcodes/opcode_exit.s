	include "defines.s"

	org $0

	; F := S0; I := S1; P := P + 2
INST_EXIT:
	move.l (sp)+,a6
	rts