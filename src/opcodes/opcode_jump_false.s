	include "defines.s"

	org $0

INST_JUMP_TRUE:
	move.l (sp)+,d0
	cmp.l #0,d0
	beq JUMP_FWD