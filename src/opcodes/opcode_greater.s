	include "defines.s"

	org $0

	; if S0 < A then A: = −1 else A: = 0 always: P: = P + 1
INST_GREATER:
	move.l (sp)+,d1
	move.l (sp)+,d2
	moveq #0,d0
	cmp.l d1,d2
	bge .done
	move.l #$FFFFFFFF,d0
.done:
	move.l d0,-(sp)