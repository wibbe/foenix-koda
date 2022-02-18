
VICKY2_MASTER_CONTROL_REG 		= $00B40000
VICKY2_MCR_GRAPH_ON				= $00000004
VICKY2_MCR_BITMAP_ON          	= $00000008
VICKY2_MCR_DOUBLE_ON          	= $00000400


GFX_FRAMEBUFFER 			= $00100000
GFX_FRAMEBUFFER_SIZE		= 320*240

	org $0

library_header:

function_count:
	dc.w 			3
functions:
	dc.l 			gfx_init
	dc.b 			0
	dc.b 			"gfx_init", 0

	dc.l 			gfx_clear
	dc.b 			0
	dc.b 			"gfx_clear", 0

	dc.l 			gfx_swap
	dc.b 			0
	dc.b 			"gfx_swap", 0


	align 2
gfx_init:
	move.l #(VICKY2_MCR_GRAPH_ON|VICKY2_MCR_BITMAP_ON|VICKY2_MCR_DOUBLE_ON),d7
	move.l d7,VICKY2_MASTER_CONTROL_REG
	rts
	

gfx_clear:
	move.l #GFX_FRAMEBUFFER,a0
	move.l #(GFX_FRAMEBUFFER_SIZE/4),d0
.loop:
	move.l #0,(a0)+
	dbra d0,.loop
	rts


gfx_swap:
	move.l #GFX_FRAMEBUFFER,a0
	move.l #(GFX_FRAMEBUFFER_SIZE/4),d0
	move.l #$AAAA,a1
.loop:
	move.l (a0)+,(a1)+
	dbra d0,.loop
	rts