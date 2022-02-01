	include "defines.s"

	org $0

INST_LOGNOT:
	move.l (sp)+,d1
	moveq #0,d0
	clr.l d0
	cmp.l #0,d1
	bne done
	move.l #$ffffffff,d0
done:
	move.l d0,-(sp)