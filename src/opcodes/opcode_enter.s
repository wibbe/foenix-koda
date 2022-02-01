	include "defines.s"

	org $0

	; P := P − 1; S0 := F; F := P
INST_ENTER:
	move.l a6,-(sp)
	move.l sp,a6