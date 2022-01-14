; VSM Instructions
;
; - A (d0) will denote the accumulator
; - S will denote the stack
; - I will denote the instruction pointer
; - P (a7/sp) will denote the stack pointer
; - F (a6) will denote the frame pointer
; - S0 will denote the element on top of the stack
; - S1 will denote the second element on the stack
; - decrementing P will add an element to the stack
; - incrementing P will remove an element from the stack
; - w, v will indicate machine words
; - a will indicate an address (which has to be relocated)
; - [x] will indicate the value at address x
; - b[x] will indicate the byte at address x
;
; CG_PUSH		P: = P − 1; S0: = A
; CG_CLEAR		A: = 0
; CG_LDVAL w		P: = P − 1; S0: = A; A: = w
; CG_LDADDR a 		P: = P − 1; S0: = A; A: = a
; CG_LDLREF w 		P: = P − 1; S0: = A; A: = F + w
; CG_LDGLOB a 		P: = P − 1; S0: = A; A: = [a]
; CG_LDLOCL w		P: = P − 1; S0: = A; A: = [F + w]
; CG_STGLOB a 		[a]: = A; A: = S0; P: = P + 1
; CG_STLOCL w 		[F + w]: = A; A: = S0; P: = P + 1
; CG_STINDR 		[S0]: = A; P: = P + 1
; CG_STINDB 		b[S0]: = A; P: = P + 1
; CG_INCGLOB a v 	[a] := [a] + v
; CG_INCLOCL w v 	[F + w]: = [F + w] + v
; CG_INC            [A] := [A] + 1
; CG_ALLOC w		P: = P − w
; CG_DEALLOC w 		P: = P + w
; CG_LOCLVEC   		w: = P; P: = P − 1; S0: = w
; CG_GLOBVEC a 		[a]: = P
; CG_INDEX 		A: = 4 ⋅ A + S0; P: = P + 1
; CG_DEREF  		A: = [A]
; CG_INDXB 		A: = A + S0; P: = P + 1
; CG_DREFB		A: = b[A]
; CG_CALL w		P: = P − 1; S0: = I; I: = w
; CG_JUMPFWD w		I: = w;
; CG_JUMPBACK w		I: = w;
; CG_JMPFALSE w		if S0 = 0, then I: = w; always: P: = P + 1
; CG_JMPTRUE w		if S0 ≠ 0, then I: = w; always: P: = P + 1
; CG_FOR w		if S0 ≥ A, then I: = w; always: P: = P + 1
; CG_ENTER		P: = P − 1; S0: = F; F: = P
; CG_EXIT			F: = S0; I: = S1; P: = P + 2
; CG_HALT w		halt program execution, return w
; CG_NEG			A: = −A
; CG_INV			A: = bitwise complement ofA
; CG_LOGNOT		if A = 0 then A: = −1 else A: = 0
; CG_ADD 			A: = S0 + A; P: = P + 1
; CG_SUB 			A: = S0 − A; P: = P + 1
; CG_MUL 			A: = S0 ⋅ A; P: = P + 1
; CG_DIV 			A: = S0 div A; P: = P + 1
; CG_MOD 			A: = S0 mod A; P: = P + 1
; (x div y is the integer quotient of x and y and x mod y is the
; remainder of the integer division.)
; CG_AND 			A: = S0 AND A; P: = P + 1
; CG_OR 			A: = S0 OR A; P: = P + 1
; CG_XOR 			A: = S0 XOR A; P: = P + 1
; (x AND y is the logical AND, x OR y is the logical OR, and
; x XOR y is the logical exclusive OR of x and y.)
; CG_SHL			A: = S0 ⋅ 2A; P: = P + 1 (left shift)
; CG_SHR			A: = S0 div 2A; P: = P + 1 (r ight shift)
; CG_EQ 			if S0 = A then A: = −1 else A: = 0;
; 			always: P: = P + 1
; CG_NEQ 			if S0 ≠ A then A: = −1 else A: = 0;
; 			always: P: = P + 1
; CG_LT 			if S0 < A then A: = −1 else A: = 0;
; 			always: P: = P + 1
; CG_GT 			if S0 > A then A: = −1 else A: = 0;
; 			always: P: = P + 1
; CG_LE 			if S0 ≤ A then A: = −1 else A: = 0;
; 			always: P: = P + 1
; CG_GE 			if S0 ≥ A then A: = −1 else A: = 0;
; 			always: P: = P + 1


	org $010000


SYSCALL0:
	move.l d0,-(sp)
	move.l a6,-(sp)
	move.l (12,sp),d0
	trap #15
	move.l (sp)+,a6
	move.l (sp)+,d0				; TODO: This will not work, we will not get any result back from the syscall!!!
	rts

SYSCALL1:
	move.l d0,-(sp)
	move.l a6,-(sp)
	move.l (12,sp),d1
	move.l (16,sp),d0
	trap #15
	move.l (sp)+,a6
	move.l (sp)+,d0				; TODO: This will not work, we will not get any result back from the syscall!!!
	rts

SYSCALL2:
	move.l d0,-(sp)
	move.l a6,-(sp)
	move.l (12,sp),d2
	move.l (16,sp),d1
	move.l (20,sp),d0
	trap #15
	move.l (sp)+,a6
	move.l (sp)+,d0				; TODO: This will not work, we will not get any result back from the syscall!!!
	rts

SYSCALL3:
	move.l d0,-(sp)
	move.l a6,-(sp)
	move.l (12,sp),d3
	move.l (16,sp),d2
	move.l (20,sp),d1
	move.l (24,sp),d0
	trap #15
	move.l (sp)+,a6
	move.l (sp)+,d0				; TODO: This will not work, we will not get any result back from the syscall!!!
	rts

MEMSCAN:
	move.l (4,sp),d1 			; copy length
	move.l (8,sp),d2 			; copy byte to search for
	move.l (12,sp),a0			; copy pointer to byte data
	move.l a0,a1 				; copy start address to our iterator
	move.l a0,a2 				; calculate end position
	add.l d1,a2					; 
memscan_loop:
	cmp.l a1,a2					; are we at the end yet?
	beq memscan_no_result

	clr.l d3
	move.b (a1)+,d3				; fetch next byte to check
	cmp.l d3,d2 				; have we found the byte we are looking for?
	beq memscan_found_byte
	bra memscan_loop 			; loop back

memscan_found_byte:
	move.l a1,d0 				; move iterator to return register
	sub.l a0,d0					; subtract start position from iterator to get byte position
	subq.l #1,d0 				; take into account that iterator as been moved to next char
	rts

memscan_no_result:
	move.l #-1,d0				; return negative value if byte was not found
	rts

MEMCOPY:
	move.l (12,sp),a0 			; fetch destination pointer
	move.l (8,sp),a1			; fetch source pointer
	move.l (4,sp),d1			; fetch byte count to copy
memcopy_loop:
	move.b (a1)+,(a0)+
	dbra d1,memcopy_loop
	rts

;* 'PRTNUM' prints the 32 bit number in D1, leading blanks are added if
;* needed to pad the number of spaces to the number in D4.
;* However, if the number of digits is larger than the no. in
;* D4, all digits are printed anyway. Negative sign is also
;* printed and counted in, positive sign is not.
;PRTNUM	MOVE.L	D1,D3		save the number for later
;	MOVE	D4,-(SP)	save the width value
;	MOVE.B	#$FF,-(SP)	flag for end of digit string
;	TST.L	D1		is it negative?
;	BPL	PN1		if not
;	NEG.L	D1		else make it positive
;	SUBQ	#1,D4		one less for width count
;PN1	DIVU	#10,D1		get the next digit
;	BVS	PNOV		overflow flag set?
;	MOVE.L	D1,D0		if not, save remainder
;	AND.L	#$FFFF,D1	strip the remainder
;	BRA	TOASCII 	skip the overflow stuff
;PNOV	MOVE	D1,D0		prepare for long word division
;	CLR.W	D1		zero out low word
;	SWAP	D1		high word into low
;	DIVU	#10,D1		divide high word
;	MOVE	D1,D2		save quotient
;	MOVE	D0,D1		low word into low
;	DIVU	#10,D1		divide low word
;	MOVE.L	D1,D0		D0 = remainder
;	SWAP	D1		R/Q becomes Q/R
;	MOVE	D2,D1		D1 is low/high
;	SWAP	D1		D1 is finally high/low
;TOASCII SWAP	D0		get remainder
;	MOVE.B	D0,-(SP)	stack it as a digit
;	SWAP	D0
;	SUBQ	#1,D4		decrement width count
;	TST.L	D1		if quotient is zero, we're done
;	BNE	PN1
;	SUBQ	#1,D4		adjust padding count for DBRA
;	BMI	PN4		skip padding if not needed
;PN3	MOVE.B	#' ',D0         display the required leading spaces
;	BSR	GOOUT
;	DBRA	D4,PN3
;PN4	TST.L	D3		is number negative?
;	BPL	PN5
;	MOVE.B	#'-',D0         if so, display the sign
;	BSR	GOOUT
;PN5	MOVE.B	(SP)+,D0	now unstack the digits and display
;	BMI	PNRET		until the flag code is reached
;	ADD.B	#'0',D0         make into ASCII
;	BSR	GOOUT
;	BRA	PN5
;PNRET	MOVE	(SP)+,D4	restore width value
;	RTS

;
; ===== Multiplies the 32 bit values in D0 and D1, returning
;       the 32 bit result in D0.
;
MULT32:
    move.l  d1,d4
    eor.l   d0,d4           ; see if the signs are the same
    tst.l   d0              ; take absolute value of d0
    bpl     mlt1
    neg.l   d0
mlt1:
    tst.l   d1              ; take absolute value of d1
    bpl     mlt2
    neg.l   d1
mlt2:
    cmp.l   #$ffff,d1       ; is second argument <= 16 bits?
    bls     mlt3            ; ok, let it through
    exg     d0,d1           ; else swap the two arguments
    cmp.l   #$ffff,d1       ; and check 2nd argument again
    bhi.w   ovflow          ; one of them must be 16 bits
mlt3:
    move    d0,d2           ; prepare for 32 bit x 16 bit multiply
    mulu    d1,d2           ; multiply low word
    swap    d0
    mulu    d1,d0           ; multiply high word
    swap    d0
; *** rick murray's bug correction follows:
    tst     d0              ; if lower word not 0, then overflow
    bne.w   ovflow          ; if overflow, say "how?"
    add.l   d2,d0           ; d0 now holds the product
    bmi.w   ovflow          ; if sign bit set, it's an overflow
    tst.l   d4              ; were the signs the same?
    bpl     mltret
    neg.l   d0              ; if not, make the result negative
mltret:
    rts

ovflow:
	moveq	#0,d0
    bra     mltret

;
; ===== Divide the 32 bit value in D0 by the 32 bit value in D1.
;       Returns the 32 bit quotient in D0, remainder in D1.
;
DIV32:
    move.l  d1,d2
    move.l  d1,d4
    eor.l   d0,d4           ; see if the signs are the same
    tst.l   d0              ; take absolute value of d0
    bpl     div1
    neg.l   d0
div1:
	tst.l   d1              ; take absolute value of d1
    bpl     div2
    neg.l   d1
div2:
    moveq   #31,d3          ; iteration count for 32 bits
	move.l  d0,d1
    clr.l   d0
div3:
    add.l   d1,d1           ; (This algorithm was translated from
    addx.l  d0,d0           ; the divide routine in Ron Cain's
    beq     div4            ; Small-C run time library.)
    cmp.l   d2,d0
    bmi     div4
    addq.l  #1,d1
    sub.l   d2,d0
div4:
    dbra    d3,div3
    exg     d0,d1           ; put rem. & quot. in proper registers
    tst.l   d4              ; were the signs the same?
    bpl     divrt
    neg.l   d0              ; if not, results are negative
    neg.l   d1
divrt:
    rts


CG_INIT:
    move.l (4,sp),d0            ; pop the parameter count supplied from the system
    move.l (8,sp),d1            ; pop the parameters list supplied from the system
	move.l #$FEDCBA98,sp 		; setup a new stack pointer at the end of the HEAP
	move.l d0,-(sp)				; push parameter count
	move.l d1,-(sp)				; push parameter list, these will be used as arguments to main()

CG_PUSH:	; P: = P − 1; S0: = A
	move.l d0,-(sp)

CG_CLEAR:	; A: = 0
	clr.l d0

CG_LDVAL: 	; w	P: = P − 1; S0: = A; A: = w
	move.l #$FEDCBA98,d0

CG_LDADDR: 	; a	P: = P − 1; S0: = A; A: = a
	move.l #$FEDCBA98,d0

CG_LDLREF: 	; w 	P: = P − 1; S0: = A; A: = F + w
	move.l a6,d0
	add.l #$FEDCBA98,d0

CG_LDGLOB: 		; a	P: = P − 1; S0: = A; A: = [a]
	move.l $FEDCBA98,d0

G_LDLOCL: 	; w	P: = P − 1; S0: = A; A: = [F + w]
	move.l $FED(a6),d0

CG_STGLOB: 	; a	[a]: = A; A: = S0; P: = P + 1
	move.l d0,$FEDCAB98

CG_STLOCL:	; w	[F + w]: = A; A: = S0; P: = P + 1
	move.l d0,$FED(a6)

CG_STINDR: 	; [S0]: = A; P: = P + 1
	move.l (sp)+,a5
	move.l d0,(a5)

CG_STINDB:	; b[S0]: = A; P: = P + 1
	move.l (sp)+,a5
	move.b d0,(a5)

CG_INCGLOB:	; a 	[a]: = [a] + 1
	add.l #1,$FEDCAB98

CG_INCLOCL: 	;w  	[F + w]: = [F + w] + 1
	add.l #1,$FED(a6)

CG_DECGLOB:	; a 	[a]: = [a] + 1
	sub.l #1,$FEDCAB98

CG_DECLOCL: 	;w  	[F + w]: = [F + w] + 1
	sub.l #1,$FED(a6)

CG_INC:			; [A] := [A] + 1
	move.l d0,a5
	addq.l #1,(a5)


CG_ALLOC:	; w	P: = P − w
	suba.l #$FEDCBA98,a7

CG_DEALLOC:	; w	P: = P + w
	adda.l #$FEDCBA98,a7

CG_LOCLVEC:	;w := P; P := P − 1; S0 := w
	move.l a7,a5
	move.l a5,-(sp)

CG_GLOBVEC:	; a	[a]: = P
	move.l a7,$01020304

CG_INDEX:	; A := 4 * A + S0; P := P + 1
	move.l (sp)+,d1
	lsl.l #2,d0
	add.l d1,d0

CG_DEREF:	; A := [A]
	move.l d0,a5
	move.l (a5),d0

CG_INDXB:	; A := A + S0; P := P + 1
	move.l (sp)+,d1
	add.l d1,d0

CG_DREFB:	; A := b[A]
	move.l d0,a5
	clr.l d0
	move.b (a5),d0

CG_CALL:	; w 	P := P − 1; S0 := I; I := w
	jsr $FEDCBA98

CG_JUMPFWD:	; w 	I: = w;
	bra CG_JMPTRUE

CG_JUMPBACK:	; w	I: = w;
	bra CG_PUSH

CG_JMPFALSE:	; w	if S0 = 0, then I: = w; always: P: = P + 1
	cmp.l #0,d0
	beq $ABCD

CG_JMPTRUE:	; w	if S0 ≠ 0, then I: = w; always: P: = P + 1
	cmp.l #0,d0
	bne $ABCD

CG_FOR:		; w	if S0 ≥ A, then I: = w; always: P: = P + 1
	move.l (sp)+,d1
	cmp.l d0,d1
	bge $ABCD

CG_ENTER:	;	P: = P − 1; S0: = F; F: = P
	move.l a6,-(sp)
	move.l sp,a6

CG_EXIT:	;	F: = S0; I: = S1; P: = P + 2
	move.l (sp)+,a6
	rts

CG_NEG:		;	A := −A
	neg.l d0

CG_INV:		;	A := bitwise complement ofA
	not.l d0

CG_LOGNOT:	;	if A = 0 then A: = −1 else A: = 0
	move.l d0,d1
	clr.l d0
	cmp.l #0,d1
	bne lognot_done
	move.l #$ffffffff,d0
lognot_done:

CG_ADD:		;	A := S0 + A; P := P + 1
	move.l (sp)+,d1
	add.l d1,d0

CG_SUB:		;	A: = S0 − A; P: = P + 1
	move.l (sp)+,d1
	exg.l d0,d1
	sub.l d1,d0

CG_MUL:		;	A: = S0 ⋅ A; P: = P + 1
	move.l (sp)+,d1
	jsr $FEDCBA98

CG_DIV:		;	A: = S0 div A; P: = P + 1
	move.l d0,d1
	move.l (sp)+,d0
	jsr $FEDCBA98

CG_MOD:		;	A: = S0 mod A; P: = P + 1
	move.l d0,d1
	move.l (sp)+,d0
	jsr $FEDCBA98
	move.l d1,d0

CG_AND:		; A := S0 AND A; P := P + 1
	move.l (sp)+,d1
	and.l d1,d0

CG_OR:		; A := S0 OR A; P := P + 1
	move.l (sp)+,d1
	or.l d1,d0

CG_XOR:		; A: = S0 XOR A; P: = P + 1
	move.l (sp)+,d1
	eor.l d1,d0

CG_HALT:	; w		halt program execution, return w
	move.l #$FEDCBA98,d1
	clr.l d0
	trap #15

CG_EQ:		; if S0 = A then A: = −1 else A: = 0; always: P: = P + 1
	move.l (sp)+,d1
	move.l d0,d2
	move.l #0,d0
	cmp.l d1,d2
	bne eq_done
	move.l #$FFFFFFFF,d0
eq_done:

CG_NEQ: 	; if S0 ≠ A then A: = −1 else A: = 0; always: P: = P + 1
	move.l (sp)+,d1
	move.l d0,d2
	move.l #0,d0
	cmp.l d1,d2
	beq neq_done
	move.l #$FFFFFFFF,d0
neq_done:

CG_LT: 		; if S0(d1) < A(d2) then A: = −1 else A: = 0 always: P: = P + 1
	move.l (sp)+,d1
	move.l d0,d2
	move.l #0,d0
	cmp.l d1,d2
	ble lt_done 		; d1 >= d2
	move.l #$FFFFFFFF,d0
lt_done:	

CG_GT:		; if S0 > A then A: = −1 else A: = 0 always: P: = P + 1
	move.l (sp)+,d1
	move.l d0,d2
	move.l #0,d0
	cmp.l d1,d2
	bge gt_done 		; d1 <= d2
	move.l #$FFFFFFFF,d0
gt_done:

CG_LE:		; if S0 ≤ A then A: = −1 else A: = 0; always: P: = P + 1
	move.l (sp)+,d1
	move.l d0,d2
	move.l #0,d0
	cmp.l d1,d2
	blt le_done 		; d1 > d2
	move.l #$FFFFFFFF,d0
le_done:	

CG_GE:		; if S0 ≥ A then A: = −1 else A: = 0; always: P: = P + 1
	move.l (sp)+,d1
	move.l d0,d2
	move.l #0,d0
	cmp.l d1,d2
	bgt ge_done 		; d1 < d2
	move.l #$FFFFFFFF,d0
ge_done:

CG_SHL:		;	A := S0 ⋅ 2A; P := P + 1 (left shift)
	move.l (sp)+,d1
	lsl.l d0,d1
	move.l d1,d0

CG_SHR:		;	A := S0 div 2A; P := P + 1 (r ight shift)
	move.l (sp)+,d1
	lsr.l d0,d1
	move.l d1,d0