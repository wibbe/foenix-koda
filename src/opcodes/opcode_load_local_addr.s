	include "defines.s"

	org $0

INST_LOAD_LOCAL_ADDR:
	move.l a6,d7
	add.l #LONG_VALUE,d7
	;move.l d7,-(sp)	<- This instruction is created from kode

	;move.l a6,d7
	;add.l #LONG_VALUE,d7
	;move.l d7,-(sp)