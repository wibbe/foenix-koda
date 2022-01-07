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
; CG_INCGLOB a v 	[a]: = [a] + v
; CG_INCLOCL w v 	[F + w]: = [F + w] + v
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
	move.l (sp)+,d0
	rts

SYSCALL1:
	move.l d0,-(sp)
	move.l a6,-(sp)
	move.l (12,sp),d1
	move.l (16,sp),d0
	trap #15
	move.l (sp)+,a6
	move.l (sp)+,d0
	rts

SYSCALL2:
	move.l d0,-(sp)
	move.l a6,-(sp)
	move.l (12,sp),d2
	move.l (16,sp),d1
	move.l (20,sp),d0
	trap #15
	move.l (sp)+,a6
	move.l (sp)+,d0
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
	move.l (sp)+,d0
	rts

CG_INIT:


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
	move.l 1(a6),d0
	move.l 4(a6),d0
	move.l -1(a6),d0

CG_STGLOB: 	; a	[a]: = A; A: = S0; P: = P + 1
	move.l d0,$FEDCAB98
	move.l (sp)+,d0

CG_STLOCL:	; w	[F + w]: = A; A: = S0; P: = P + 1
	move.l d0,$FED(sp)
	move.l (sp)+,d0

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

CG_ALLOC:	; w	P: = P − w
	suba.l #$FEDCBA98,a7

CG_DEALLOC:	; w	P: = P + w
	adda.l #$FEDCBA98,a7

CG_LOCLVEC:	;w := P; P := P − 1; S0 := w
	move.l a7,a5
	move.l a5,-(sp)

CG_GLOBVEC:	; a	[a]: = P
	move.l a7,$FEDCBA98

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
	;jmp $FEDCBA98
	bra CG_JMPTRUE

CG_JUMPBACK:	; w	I: = w;
	;jmp $FEDCBA98
	bra CG_PUSH

CG_JMPFALSE:	; w	if S0 = 0, then I: = w; always: P: = P + 1
	;move.l (sp)+,d1
	cmp.l #0,d0
	beq $ABCD

CG_JMPTRUE:	; w	if S0 ≠ 0, then I: = w; always: P: = P + 1
	;move.l (sp)+,d1
	cmp.l #0,d0
	bne $ABCD

CG_FOR:		; w	if S0 ≥ A, then I: = w; always: P: = P + 1
	move.l (sp)+,d1
	cmp.l d1,d0
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
	move.l d1,$00B03020
	move.l d0,$00B03024
	move.l $00B03028,d0

CG_DIV:		;	A: = S0 div A; P: = P + 1
	move.l (sp)+,d1
	move.l d1,$00B03060
	move.l d0,$00B03064
	move.l $00B03068,d0

CG_MOD:		;	A: = S0 mod A; P: = P + 1
	move.l (sp)+,d1
	move.l d1,$00B03060
	move.l d0,$00B03064
	move.l $00B0306C,d0

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