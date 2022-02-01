	include "defines.s"

	org $0

	; P := P − 1; S0 := A; A := [a]
INST_STORE_GLOBAL:
	move.l (sp)+,d0
	move.l d0,ADDRESS