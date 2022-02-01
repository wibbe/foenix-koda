	include "defines.s"	

	org 	$0

CG_LOAD_VALUE:
	move.l #LONG_VALUE,-(sp)
	;move.l d0,-(sp)