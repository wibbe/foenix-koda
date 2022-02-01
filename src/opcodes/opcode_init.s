	include "defines.s"

	org $0

INST_INIT:
    move.l (4,sp),d0            ; pop the parameter count supplied from the system
    move.l (8,sp),d1            ; pop the parameters list supplied from the system
	move.l #LONG_VALUE,sp 		; setup a new stack pointer at the end of the HEAP
	move.l d0,-(sp)				; push parameter count
	move.l d1,-(sp)				; push parameter list, these will be used as arguments to main()	