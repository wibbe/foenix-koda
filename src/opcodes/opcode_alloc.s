	include "defines.s"

	org $0

	; P := P − w
INST_ALLOC:
	suba.l #LONG_VALUE,a7
