	org $0

MEMSCAN:
	move.l (4,sp),d1 			; copy length
	move.l (8,sp),d2 			; copy byte to search for
	move.l (12,sp),a0			; copy pointer to byte data
	move.l a0,a1 				; copy start address to our iterator
	move.l a0,a2 				; calculate end position
	add.l d1,a2					; 
.memscan_loop:
	cmp.l a1,a2					; are we at the end yet?
	beq .memscan_no_result

	clr.l d3
	move.b (a1)+,d3				; fetch next byte to check
	cmp.l d3,d2 				; have we found the byte we are looking for?
	beq .memscan_found_byte
	bra .memscan_loop 			; loop back

.memscan_found_byte:
	move.l a1,d6 				; move iterator to return register
	sub.l a0,d6					; subtract start position from iterator to get byte position
	subq.l #1,d6 				; take into account that iterator as been moved to next char
	rts

.memscan_no_result:
	move.l #-1,d6				; return negative value if byte was not found
	rts
