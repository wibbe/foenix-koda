	include "defines.s"

	org $0

	; [S0] := A; P := P + 1
INST_STORE_INDIRECT_WORD:
	move.l (sp)+,d0
	move.l (sp)+,a5
	move.l d0,(a5)
