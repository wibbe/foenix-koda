    org $0
    
MUL32:
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