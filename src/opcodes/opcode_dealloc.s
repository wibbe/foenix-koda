	include "defines.s"

	org $0

	; P := P + w
INST_DEALLOC:
	adda.l #LONG_VALUE,a7
