
VICKY2_MASTER_CONTROL_REG 		= $00B40000
VICKY2_MCR_GRAPH_ON				= $00000004
VICKY2_MCR_BITMAP_ON          	= $00000008
VICKY2_MCR_DOUBLE_ON          	= $00000400


GFX_BACK_BUFFER_SIZE		= 320*240
GFX_BUFFER_STRIDE			= 320

function: macro
	dc.l 	\2
	dc.b 	\3
	dc.b 	\1,0
endm


	org $0

library_header:
	dc.w 			5
	function "gfx_init", gfx_init, 1
	function "gfx_clear", gfx_clear, 0
	function "gfx_swap", gfx_swap, 0
	function "gfx_blit8", gfx_blit8, 3
	function "gfx_backbuffer_size", gfx_backbuffer_size, 0
	;function "gfx_blit16", gfx_blit16, 3

	align 2
gfx_back_buffer:
	dc.l 	0


gfx_init:
	move.l (4,sp),d0			; pointer to back-buffer
	lea gfx_back_buffer(pc),a0
	move.l d0,(a0)

	; Use 320x240 resolution with bitmap graphics on
	move.l #(VICKY2_MCR_GRAPH_ON|VICKY2_MCR_BITMAP_ON|VICKY2_MCR_DOUBLE_ON),d7
	move.l d7,VICKY2_MASTER_CONTROL_REG

	moveq #0,d7
	move.l d7,$00B40104		; Setup bitmap 0 address to zero (start of vram)
	move.l d7,$00B40008		; Turn off borders

	; Enable bitmap 0
	moveq #1,d7
	move.l d7,$00B40100
	rts


gfx_backbuffer_size:
	move.l #GFX_BACK_BUFFER_SIZE,d6
	rts

gfx_clear:
	lea gfx_back_buffer(pc),a0
	move.l #(GFX_BACK_BUFFER_SIZE/4),d0
.loop:
	move.l #0,(a0)+
	dbra d0,.loop
	rts


gfx_swap:
	lea gfx_back_buffer(pc),a0
	move.l #(GFX_BACK_BUFFER_SIZE/4),d0
	move.l #$AAAA,a1
.loop:
	move.l (a0)+,(a1)+
	dbra d0,.loop
	rts


; Blit a 8x8 image to the back-buffer
gfx_blit8:
	move.l (4,sp),a0 		; pointer to image data
	move.l (8,sp),d1 		; y-coordinate
	move.l (12,sp),d0 		; x-coordinate

	move.l d0,d2
	and.l #$03,d2
	beq .blit4

.blit1:
	bsr gfx_start_address
	move.l #64,d2
.blit1_loop:
	move.b (a0)+,(a1)+
	dbra d2,.blit1_loop
	rts

.blit4:
	bsr gfx_start_address
	move.l #16,d2
.blit4_loop:	
	move.l (a0)+,(a1)+		; row 1
	dbra d2,.blit4_loop
	rts


; Blit a 16x16 image to the back-buffer
gfx_blit16:
	move.l (sp)+,a0 		; pointer to image data
	move.l (sp)+,d1 		; y-coordinate
	move.l (sp)+,d0 		; x-coordinate
	rts



; From (x, y) coordinates in (d0, d1) calculate the
; correct start address for the back-buffer.
; Result in a1
gfx_start_address:
	move.l d1,d2 				; copy y-coordinate
	move.l d1,d3				; copy y-coordinate
	lsl.l #8,d2					; multiply by 256
	lsl.l #4,d3					; multiply by 64
	add.l d3,d2 				; add them together
	lea gfx_back_buffer(pc),a0
	add.l (a0),d2				; add base address
	add.l d0,d2 				; add x-coordinate
	move.l d2,a1				; store result in a1
	rts