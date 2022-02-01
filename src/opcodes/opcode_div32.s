    org $0

DIV32:
    move.l  d1,d2
    move.l  d1,d4
    eor.l   d0,d4           ; see if the signs are the same
    tst.l   d0              ; take absolute value of d0
    bpl     .div1
    neg.l   d0
.div1:
	tst.l   d1              ; take absolute value of d1
    bpl     .div2
    neg.l   d1
.div2:
    moveq   #31,d3          ; iteration count for 32 bits
	move.l  d0,d1
    clr.l   d0
.div3:
    add.l   d1,d1           ; (This algorithm was translated from
    addx.l  d0,d0           ; the divide routine in Ron Cain's
    beq     .div4           ; Small-C run time library.)
    cmp.l   d2,d0
    bmi     .div4
    addq.l  #1,d1
    sub.l   d2,d0
.div4:
    dbra    d3,.div3
    exg     d0,d1           ; put rem. & quot. in proper registers
    tst.l   d4              ; were the signs the same?
    bpl     .divrt
    neg.l   d0              ; if not, results are negative
    neg.l   d1
.divrt:
    rts