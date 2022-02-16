	include "defines.s"
	include "defines_gfx.s"

	org $0

gfx_clear:
	move.l #GFX_FRAMEBUFFER,a0
	move.l #(GFX_FRAMEBUFFER_SIZE/4),d0
.loop:
	move.l #0,(a0)+
	dbra d0,.loop
	rts