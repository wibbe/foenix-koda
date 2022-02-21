	
	include "opcodes/defines.s"

	org $0

	adda.l #$12000008,a7
	
	movem.l d0/d1/d2/d3,-(sp)
	movem.l (sp)+,d0/d1/d2/d3

	lsr.l d0,d1
	lsr.l d1,d1
	lsr.l d1,d0

	lsl.l d0,d1
	lsl.l d1,d1
	lsl.l d1,d0

	move.w d0,(a5)

	move.w (a5),d0
	move.w (a5),d1

	suba.l   #$12000008,A7

	or.l d0,d1
	or.l d1,d1
	or.l d1,d2

	sub.l #1234,d0
	sub.l #1234,d1
	sub.l #1234,d2
	sub.l #2234,d0
	sub.l #1234,d0
	sub.l #4,d0

	cmp.l d0,d0
	cmp.l d0,d1
	cmp.l d0,d2
	cmp.l d1,d0
	cmp.l d2,d0

	and.l d0,d0
	and.l d0,d1
	and.l d0,d2
	and.l d1,d2


	exg d1,d0
	
	sub.l d1,d0

	sub.l d0,d1

	sub.l d0,d2
	sub.l d2,d0
	sub.l d3,d0


	exg d0,d1

	trap #0
	trap #1
	trap #15

	move.l #$FFFFFFFF,d0

	bne.s done

	bne $200

	cmp.l #0,d0
done:	
	cmp.l #2,d0
	cmp.l #0,d1
	cmp.l #0,d2
	cmp.l #1,d0
	cmp.l #1,d1
	cmp.l #1,d2
	cmp.l #1,d3

	not.l d0
	not.l d1

	neg.l d0
	neg.l d1

	jsr (a5)
	jsr $FF000000

	movem.l (sp)+,d0-d3

	movem.l d0-d3,-(sp)
	movem.l d0-d4,-(sp)
	movem.l d1-d3,-(sp)
	movem.l d1-d4,-(sp)

	move.b (a5),d0
	move.b (a5),d1

	add.l d0,d1
	add.l d0,d2
	add.l d1,d0
	add.l d1,d1

	lsl.l #1,d0
	lsl.l #2,d0
	lsl.l #4,d0
	lsl.l #5,d0
	lsl.l #2,d1
	lsl.l #2,d2

	move.l sp,ADDRESS

	move.l sp,d0
	move.l sp,d1

	move.b d0,(a5)
	move.b d1,(a5)

	move.l d0,a5
	move.l d1,a5

	move.l d0,(a5)
	move.l d1,(a5)

	move.l d0,a6
	move.l d1,a6

	move.l d0,4(a6)
	move.l d1,WORD_VALUE(a6)

	move.l d0,ADDRESS
	move.l d1,ADDRESS

	move.l -4(a6),d0
	move.l 4(a6),d0

	move.l WORD_VALUE(a6),d0
	move.l WORD_VALUE(a6),d1

	move.l ADDRESS,d0
	move.l ADDRESS,d1

	add.l #LONG_VALUE,d0
	add.l #LONG_VALUE,d1
	add.l #LONG_VALUE,d2

	move.l a6,d0
	move.l a6,d1

	move.l d0,d1
	move.l d6,d3
	move.l d7,d2

	move.l (sp)+,d0
	move.l (sp)+,d1

	move.l d0,-(sp)
	move.l d1,-(sp)
	move.l d2,-(sp)

	move.l #LONG_VALUE,d0
	move.l #LONG_VALUE,d1
	move.l #LONG_VALUE,d2
	move.l #LONG_VALUE,d3
	move.l #WORD_VALUE,d0
	move.l #WORD_VALUE,d1
	move.l #WORD_VALUE,d2
	move.l #WORD_VALUE,d3

	moveq #$55,d0
	moveq #$55,d1


function: