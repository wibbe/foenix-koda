	include "defines.s"
	include "defines_gfx.s"

	org $0

gfx_swap:
	move.l #GFX_FRAMEBUFFER,a0
	move.l #(GFX_FRAMEBUFFER_SIZE/4),d0
	move.l #$AAAA,a1
.loop:
	move.l (a0)+,(a1)+
	dbra d0,.loop
	rts