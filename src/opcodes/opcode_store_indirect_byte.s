	include "defines.s"

	org $0

	; b[S0] := A; P := P + 1
INST_STORE_INDIRECT_BYTE:
	move.l (sp)+,d0
	move.l (sp)+,a5
	move.b d0,(a5)
