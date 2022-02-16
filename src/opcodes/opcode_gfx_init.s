	include "defines.s"
	include "defines_gfx.s"

	org $0

GFX_INIT:
	move.l #(VICKY2_MCR_GRAPH_ON|VICKY2_MCR_BITMAP_ON|VICKY2_MCR_DOUBLE_ON),d7
	move.l d7,VICKY2_MASTER_CONTROL_REG
	rts