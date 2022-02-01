	include "defines.s"

	org $0

	; w := P; P := P − 1; S0 := w
INST_LOCAL_VEC:
	move.l a7,a5
	move.l a5,-(sp)
